"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3
import time
import logging as log

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan
from utils.database_interface import DbInterface


class Storage(DbInterface):
    """
    This class provides local storage funxtionality

    """
    SAVE_NODE_QUERY = "INSERT OR REPLACE INTO nodes (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)"
    SAVE_PORT_QUERY = "INSERT OR REPLACE INTO ports (scan_id, node_id, node_ip, port, port_protocol, time) "\
                      "VALUES (?, ?, ?, ?, ?, ?)"
    SAVE_SCAN_QUERY = "INSERT OR REPLACE INTO scans (protocol, scanner_name, scan_start, scan_end) VALUES (?, ?, ?, ?)"
    UPDATE_SCAN_END_QUERY = "UPDATE scans set scan_end = ? WHERE (protocol=? OR (? IS NULL AND protocol IS NULL)) "\
                            "AND scanner_name=? and scan_start=?"
    SAVE_SECURITY_SCAN_DETAIL = "INSERT OR IGNORE INTO security_scans (exploit_id, exploit_app, exploit_name, " \
                                "node_id, node_ip, port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)"
    SAVE_SECURITY_SCAN_DETAIL_START = "UPDATE security_scans SET scan_start=? WHERE exploit_id=? AND exploit_app=? AND"\
                                      " exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL "\
                                      "AND port_protocol IS NULL)) AND port_number=?"
    SAVE_SECURITY_SCAN_DETAIL_END = "UPDATE security_scans SET scan_end=? WHERE exploit_id=? AND exploit_app=? AND " \
                                    "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL "\
                                    "AND port_protocol IS NULL)) AND port_number=?"
    SELECT_NODES = "SELECT node_id, node_ip, time FROM nodes INNER JOIN scans ON scan_id = scans.ROWID WHERE time>? " \
                   "AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?"
    SELECT_PORTS = "SELECT node_id, node_ip, port, port_protocol, time FROM ports INNER JOIN scans ON "\
                   "scan_id = scans.ROWID where time > ? AND (scans.protocol=? OR (? IS NULL AND "\
                   "scans.protocol IS NULL)) AND scans.scanner_name=?"
    SELECT_SCANS = "SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE (protocol=? OR "\
                   "(? IS NULL AND protocol IS NULL)) AND scanner_name=? ORDER BY scan_end DESC, scan_start ASC "\
                   "LIMIT {limit} OFFSET {offset}"
    SELECT_SCAN = "SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE (protocol=? OR "\
                  "(? IS NULL AND protocol IS NULL)) AND scanner_name=? AND scan_start=? LIMIT 1"
    SELECT_SECURITY_SCANS = "SELECT exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, " \
                            "port_number, scan_start, scan_end FROM security_scans WHERE exploit_app=? AND node_id=? " \
                            "AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) "\
                            "AND port_number=?"
    SELECT_PORTS_BY_NODE = "SELECT node_id, node_ip, port, port_protocol, time FROM ports where node_id=? "\
                           "AND node_ip=? AND time > ? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL))"
    SELECT_PORTS_BY_NODE_ALL_PROTS = "SELECT node_id, node_ip, port, port_protocol, time FROM ports where node_id=? "\
                                     "AND node_ip=? AND time > ?"
    SELECT_PORTS_BY_NODES = "SELECT node_id, node_ip, port, port_protocol, time FROM ports where ({where}) " \
                            "AND time > ? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL))"
    SELECT_PORTS_BY_NODES_ALL_PROTS = "SELECT node_id, node_ip, port, port_protocol, time FROM ports where ({where}) "\
                                      "AND time > ?"
    CLEAR_SECURITY_SCANS = "DELETE FROM security_scans WHERE scan_start >= scan_end OR scan_start IS NULL "\
                           "OR SCAN_END IS NULL"
    CREATE_SECURITY_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS security_scans (exploit_id int, exploit_app text, " \
                                  "exploit_name text, node_id int, node_ip text, port_protocol int, port_number int, " \
                                  "scan_start float, scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, "\
                                  "port_protocol, port_number))"
    CREATE_PORTS_TABLE = "CREATE TABLE IF NOT EXISTS ports (scan_id int, node_id int, node_ip text, port int, " \
                         "port_protocol int, time int, primary key (scan_id, node_id, node_ip, port, port_protocol))"
    CREATE_NODES_TABLE = "CREATE TABLE IF NOT EXISTS nodes(scan_id int, node_id int, node_ip text, time int, " \
                         "primary key (scan_id, node_id, node_ip))"
    CREATE_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS scans(protocol int, scanner_name str, scan_start int, "\
                         "scan_end int, UNIQUE (protocol, scanner_name, scan_start))"

    def __init__(self, filename="storage.sqlite3"):

        """
        Init storage

        Args:
            filename (str): filename of provided storage

        """
        self.filename = filename
        self.conn = None
        self._cursor = None

    def init_schema(self):
        """
        Initialize database schema

        Returns:
            None

        """
        self.execute(self._create_tables())
        self.execute(self._clear_security_scans())

    def connect(self):
        self.conn = sqlite3.connect(self.filename, check_same_thread=True)
        self._cursor = self.conn.cursor()

    def close(self):
        assert isinstance(self.conn, sqlite3.Connection)
        self.conn.close()
        self.conn = None
        self._cursor = None

    @property
    def cursor(self):
        """
        Returns:
            handler to the database cursor

        """
        return self._cursor

    def _save_node(self, node, scan):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            tuple

        """
        scan_id = self.get_scan_id(scan)
        return self.SAVE_NODE_QUERY, (scan_id, node.id, str(node.ip), time.time())

    def _save_nodes(self, nodes, scan):
        """
        Saves nodes into local storage

        Args:
            nodes (list):
            scan (Scan):

        Returns:
            list

        """
        scan_id = self.get_scan_id(scan)
        queries = [(self.SAVE_NODE_QUERY, (scan_id, node.id, str(node.ip), time.time())) for node in nodes]

        log.debug("Saving nodes")
        return queries

    def _get_nodes(self, pasttime, timestamp, scan):
        """
        Returns all nodes from local storage

        Args:
            pasttime (int):
            timestamp (int):
            scan (Scan):

        Returns:
            tuple

        """
        if timestamp is None:
            timestamp = time.time() - pasttime
        iana = self._protocol_to_iana(scan.protocol)
        return self.SELECT_NODES, (timestamp, iana, iana, scan.scanner)

    def _save_port(self, port):
        """
        Query for saving port scan into database

        Args:
            port (Port): port to save into storage

        Returns:
            tuple

        """
        return self.SAVE_PORT_QUERY, (0, port.node.id, str(port.node.ip), port.number,
                                      self._protocol_to_iana(port.transport_protocol), time.time())

    def _save_ports(self, ports, scan):
        """
        Queries for saving ports scans into database

        Args:
            ports (list):

        Returns:
            list

        """
        scan_id = self.get_scan_id(scan)
        queries = [(self.SAVE_PORT_QUERY, (scan_id, port.node.id, str(port.node.ip), port.number,
                                           self._protocol_to_iana(port.transport_protocol), time.time()))
                   for port in ports]

        return queries

    def _get_ports(self, pasttime, scan):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            pasttime(int)
            scan (Scan):

        Returns:
            tuple

        """
        scan_id = self.get_scan_id(scan)
        timestamp = time.time() - pasttime
        iana =        self._protocol_to_iana(scan.protocol)

        return self.SELECT_PORTS, (timestamp, iana, iana, scan.scanner)

    def _save_security_scan(self, exploit, port):
        """
        Queries for saving scan into database

        Args:
            exploit (Exploit): needs some exploit details to save into storage
            port (Port): needs some port details to save into storage

        Returns:
            list

        """

        log.debug("Saving scan details: scan_start(%s), scan_end(%s), exploit_id(%s), node_id(%s), node(%s), port(%s)",
                  port.scan.start, port.scan.end, exploit.id, port.node.id, str(port.node), str(port))
        queries = []
        iana = self._protocol_to_iana(port.transport_protocol)

        queries.append((self.SAVE_SECURITY_SCAN_DETAIL, (exploit.id, exploit.app, exploit.name, port.node.id,
                                                         str(port.node.ip), iana, port.number)))

        if port.scan.start:
            queries.append((self.SAVE_SECURITY_SCAN_DETAIL_START, (port.scan.start, exploit.id, exploit.app,
                                                                   exploit.name, port.node.id, str(port.node.ip), iana,
                                                                   iana, port.number)))

        if port.scan.end:
            queries.append((self.SAVE_SECURITY_SCAN_DETAIL_END, (port.scan.end, exploit.id, exploit.app, exploit.name,
                                                                 port.node.id, str(port.node.ip), iana, iana,
                                                                 port.number)))
        return queries

    def _save_security_scans(self, exploits, port):
        """
        Queries for saving scans into database

        Args:
            exploits (list): List of Exploits
            port (Port):

        Returns:
            list
 .

        """
        return list(query for exploit in exploits for query in self._save_security_scan(exploit=exploit, port=port))

    def _get_security_scan_info(self, port, app):
        """
        Query for scan detail for provided port and app

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        iana = self._protocol_to_iana(port.transport_protocol)
        return self.SELECT_SECURITY_SCANS, (app, port.node.id, str(port.node.ip), iana, iana, port.number)

    def _clear_security_scans(self):
        """
        Query for cleaning table

        Returns:
            tuple

        """
        log.debug('Cleaning scan details')
        return self.CLEAR_SECURITY_SCANS,

    def _create_tables(self):
        """
        List of queries for table creation

        Returns:
            list

        """
        queries = [(self.CREATE_SCANS_TABLE,),
                   (self.CREATE_SECURITY_SCANS_TABLE,),
                   (self.CREATE_PORTS_TABLE,),
                   (self.CREATE_NODES_TABLE,)]

        return queries

    def _get_ports_by_node(self, node, timestamp, protocol=None):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name
            protocol (TransportProtocol):

        Returns:
            tuple

        """
        if protocol is None:
            return self.SELECT_PORTS_BY_NODE_ALL_PROTS, (node.id, str(node.ip), timestamp)
        iana = self._protocol_to_iana(protocol)

        return self.SELECT_PORTS_BY_NODE, (node.id, str(node.ip), timestamp, iana, iana)

    def _get_ports_by_nodes(self, nodes, timestamp, protocol=None):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            nodes (list):
            timestamp (int):
            protocol (TransportProtocol):

        Returns:
            tuple

        """
        parameters = []
        for node in nodes:
            parameters.extend((node.id, str(node.ip)))

        parameters.append(timestamp)
        query = self.SELECT_PORTS_BY_NODES_ALL_PROTS

        if protocol is not None:
            iana = self._protocol_to_iana(protocol)
            parameters.extend([iana, iana])
            query = self.SELECT_PORTS_BY_NODES

        where = 'OR'.join([' (node_id=? AND node_ip=?) '] * len(nodes))

        return query.format(where=where), parameters

    def execute(self, query):
        """
        Execute query or queries.

        Args:
            query (list|tuple|str):

        Returns:
            None|tuple

        """
        if isinstance(query, list):
            log.debug("executing %i queries", len(query))
            for row in query:
                self.cursor.execute(*row)
        else:
            log.debug("executing query: %s", query)
            return self.cursor.execute(*query).fetchall()

        self.conn.commit()

    def save_node(self, node, protocol=None):
        """
        Save node to database

        Args:
            node (Node):

        Returns:
            None

        """
        return self.execute(self._save_node(node=node, protocol=protocol))

    def save_nodes(self, nodes, scan):
        """
        Save nodes to database

        Args:
            nodes (lst):

        Returns:
            None

        """
        return self.execute(self._save_nodes(nodes=nodes, scan=scan))

    def get_nodes(self, scan, pasttime=0, timestamp=None):
        """
        Get nodes from database since timestamp. If timestamp is not given, it's computed basing on pastime.

        Args:
            pasttime (int):
            timestamp (int):

        Returns:
            list - list of nodes
        """
        nodes = []

        for node in self.execute(self._get_nodes(pasttime=pasttime, timestamp=timestamp, scan=scan)):
            nodes.append(Node(node_id=node[0], ip=ipaddress.ip_address(node[1])))
        return nodes

    def save_port(self, port):
        """
        Save port to database

        Args:
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_port(port=port))

    def save_ports(self, ports, scan):
        """
        Save ports to database

        Args:
            ports (list):

        Returns:
            None

        """
        return self.execute(self._save_ports(ports=ports, scan=scan))

    def get_ports(self, scan, pasttime=900):
        """
        Get ports from database from pasttime.

        Args:
            pasttime (int):

        Returns:
            list - list of Ports

        """
        ports = []

        for port in self.execute(self._get_ports(pasttime=pasttime, scan=scan)):
            ports.append(Port(node=Node(node_id=port[0], ip=ipaddress.ip_address(port[1])), number=port[2],
                              transport_protocol=self._transport_protocol(port[3])))
        return ports

    def save_security_scan(self, exploit, port):
        """
        Save scan of port by exploit to database

        Args:
            exploit (Exploit):
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_security_scan(exploit=exploit, port=port))

    def save_security_scans(self, exploits, port):
        """
        Save scans of port to database basing on given exploits

        Args:
            exploits (list):
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_security_scans(exploits=exploits, port=port))

    def get_security_scan_info(self, port, app):
        """
        Get scan info from database

        Args:
            port (Port):
            app (str):

        Returns:
            tuple

        """
        return_value = []

        for row in self.execute(self._get_security_scan_info(port=port, app=app)):
            return_value.append({
                "exploit": Exploit(exploit_id=row[0]),
                "port": Port(node=Node(node_id=row[3], ip=ipaddress.ip_address(row[4])), number=row[6],
                             transport_protocol=self._transport_protocol(row[5])),
                "scan_start": row[7] or 0.,
                "scan_end": row[8] or 0.,
                "exploit_name": row[2]
            })

        return return_value

    def clear_security_scans(self):
        """
        Clear broken scan details

        Returns:
            None

        """
        return self.execute(self._clear_security_scans())

    def create_tables(self):
        """
        Create tables in storage

        Returns:
            None

        """
        return self.execute(self._create_tables())

    def get_ports_by_node(self, node, pasttime=0, timestamp=None, protocol=None):
        """
        Get open ports of node since timestamp or from pasttime if timestamp is not given.

        Args:
            node (Node):
            pasttime (int):
            timestamp (int):
            protocol (int):

        Returns:
            list - list of Nodes

        """
        ports = []
        if timestamp is None:
            timestamp = time.time() - pasttime

        for row in self.execute(self._get_ports_by_node(node=node, timestamp=timestamp, protocol=protocol)):
            port = Port(node=node, number=row[2], transport_protocol=self._transport_protocol(row[3]))
            port.scan = Scan(start=port.node.scan.start)
            ports.append(port)

        return ports

    def get_ports_by_nodes(self, nodes, pasttime=0, timestamp=None, protocol=None):
        """
        Get open ports of nodes since timestamp or from pasttime if timestamp is not given.

        Args:
            nodes (list):
            pasttime (int):
            timestamp (int):
            protocol (int):

        Returns:
            list - list of Ports

        """
        ports = []

        if not nodes:
            return []

        if timestamp is None:
            timestamp = time.time() - pasttime

        for row in self.execute(self._get_ports_by_nodes(nodes=nodes, timestamp=timestamp, protocol=protocol)):
            node = nodes[nodes.index(Node(node_id=row[0], ip=ipaddress.ip_address(row[1])))]
            port = Port(node=node, number=row[2], transport_protocol=self._transport_protocol(row[3]))
            port.scan = Scan(start=port.node.scan.start)
            ports.append(port)

        return ports

    def _transport_protocol(self, number):
        """
        Convert database protocol to TransportProtocol

        Args:
            number (int|None):

        Returns:
            TransportProtocol|None - None if number is None

        """
        if number is None:
            return None

        return TransportProtocol.from_iana(number)

    def _protocol_to_iana(self, protocol):
        """
        Convert database protocol to TransportProtocol

        Args:
            protocol (TransportProtocol):

        Returns:
            int|None - None if number is None

        """
        if protocol is None:
            return None

        return protocol.iana

    def _save_scan(self, scan):
        """
        Queries for saving scan into database

        Args:
            scan (Scan):

        Returns:
            list

        """
        return self.SAVE_SCAN_QUERY, (self._protocol_to_iana(scan.protocol), scan.scanner, scan.start, scan.end)

    def _update_scan(self, scan):
        iana = self._protocol_to_iana(scan.protocol)
        return self.UPDATE_SCAN_END_QUERY, (scan.end, iana, iana, scan.scanner, scan.start)

    def _get_scans(self, protocol, scanner_name, limit=2, offset=0):
        iana = self._protocol_to_iana(protocol)
        return self.SELECT_SCANS.format(limit=limit, offset=offset), (iana, iana, scanner_name)

    def _get_scan(self, scan):
        iana = self._protocol_to_iana(scan.protocol)
        return self.SELECT_SCAN, (iana, iana, scan.scanner, scan.start)

    def save_scan(self, scan):
        """
        Save scan into storage

        Args:
            scan (Scan):

        Returns:

        """
        return self.execute(self._save_scan(scan=scan))

    def update_scan(self, scan):
        """
        Update scan in storage

        Args:
            scan (Scan):

        Returns:

        """
        return self.execute(self._update_scan(scan=scan))

    def get_scan_id(self, scan):
        """
        Get scan_id

        Args:
            scan (Scan):

        Returns:
            int

        """
        data = self.execute(self._get_scan(scan=scan))
        if not data:
            return None

        return data[0][0]

    def get_scans(self, protocol, scanner_name, amount=2):
        """
        Obtain scans from storage. Scans are taken from newest to oldest

        Args:
            protocol (TransportProtocol):
            scanner_name (str):
            amount (int):

        Returns:
            list - list of scans

        """
        scans = []

        for row in self.execute(self._get_scans(protocol=protocol, scanner_name=scanner_name, limit=amount, offset=0)):
            scan = Scan(start=row[3], end=row[4], protocol=self._transport_protocol(row[1]))
            scans.append(scan)

        return scans
