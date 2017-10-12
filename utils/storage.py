"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3
import time
import logging as log

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan, Vulnerability, PortScan, SecurityScan
from utils.database_interface import DbInterface
from scans.tcp_scanner import TCPScanner
from scans.udp_scanner import UDPScanner


class Storage(DbInterface):
    """
    This class provides local storage funxtionality

    """
    GET_LAST_ROWID = "SELECT last_insert_rowid()"

    CREATE_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS scans(protocol int, scanner_name str, scan_start int, "\
                         "scan_end int, UNIQUE (protocol, scanner_name, scan_start))"
    SAVE_SCAN_QUERY = "INSERT INTO scans (protocol, scanner_name, scan_start, scan_end) VALUES (?, ?, ?, ?)"
    UPDATE_SCAN_END_QUERY = "UPDATE scans set scan_end = ? WHERE ROWID=?"
    SELECT_SCAN_BY_ID = "SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE ROWID=?"
    SELECT_SCANS = "SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE (protocol=? OR "\
                   "(? IS NULL AND protocol IS NULL)) AND scanner_name=? ORDER BY scan_end DESC, scan_start ASC "\
                   "LIMIT {limit} OFFSET {offset}"
    SELECT_SCAN = "SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE (protocol=? OR "\
                  "(? IS NULL AND protocol IS NULL)) AND scanner_name=? AND scan_start=? LIMIT 1"

    CREATE_NODES_TABLE = "CREATE TABLE IF NOT EXISTS nodes_scans(scan_id int, node_id int, node_ip text, time int, " \
                         "primary key (scan_id, node_id, node_ip))"
    SAVE_NODE_QUERY = "INSERT INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)"
    SELECT_NODES = "SELECT node_id, node_ip, time FROM nodes_scans INNER JOIN scans ON scan_id = scans.ROWID WHERE" \
                   " time>? AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?"
    SELECT_SCANS_BY_NODE = "SELECT scans.ROWID, protocol, scanner_name, scan_start, scan_end FROM scans "\
                           "LEFT JOIN nodes_scans ON scans.ROWID = nodes_scans.scan_id WHERE node_id=? AND node_ip=? "\
                           " AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?"\
                           "ORDER BY scan_end DESC, scan_start ASC LIMIT {limit} OFFSET {offset}"
    SELECT_SCAN_NODES = "SELECT node_id, node_ip, time, scan_id FROM nodes_scans WHERE scan_id=?"

    CREATE_PORTS_TABLE = "CREATE TABLE IF NOT EXISTS ports_scans (scan_id int, node_id int, node_ip text, port int, " \
                         "port_protocol int, time int, primary key (scan_id, node_id, node_ip, port, port_protocol))"
    SAVE_PORT_QUERY = "INSERT OR REPLACE INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) "\
                      "VALUES (?, ?, ?, ?, ?, ?)"
    SELECT_PORTS = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans INNER JOIN scans ON "\
                   "scan_id = scans.ROWID where time > ? AND (scans.protocol=? OR (? IS NULL AND "\
                   "scans.protocol IS NULL)) AND scans.scanner_name=?"
    SELECT_PORTS_BY_ID = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans WHERE ROWID=?"
    SELECT_PORTS_BY_NODE_AND_SCAN = "SELECT node_id, node_ip, port, port_protocol, time, ROWID FROM ports_scans where "\
                                    "node_id=? AND node_ip=? AND scan_id=?"
    SELECT_PORTS_BY_NODES = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans where ({where}) " \
                            "AND time > ? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL))"
    SELECT_PORTS_BY_NODES_ALL_PROTS = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans where"\
                                      " ({where}) AND time > ?"
    SELECT_PORTS_BY_NODES_PORTDETECTION = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans" \
                                          " INNER JOIN scans ON scan_id = scans.ROWID  where ({where}) AND time > ?" \
                                          " AND (scans.scanner_name=? or scans.scanner_name=?)"

    CREATE_SECURITY_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS security_scans (scan_id int, exploit_id int, " \
                                  "exploit_app text, exploit_name text, node_id int, node_ip text, port_protocol int, "\
                                  "port_number int, sec_scan_start float, sec_scan_end float, PRIMARY KEY (scan_id, "\
                                  "exploit_id, node_id, node_ip, port_protocol, port_number))"
    SAVE_SECURITY_SCAN_DETAIL = "INSERT OR IGNORE INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name,"\
                                " node_id, node_ip, port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    SAVE_SECURITY_SCAN_DETAIL_START = "UPDATE security_scans SET sec_scan_start=? WHERE exploit_id=? AND "\
                                      "exploit_app=? AND exploit_name=? AND node_id=? AND node_ip=? AND "\
                                      "(port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? "\
                                      "AND scan_id=?"
    SAVE_SECURITY_SCAN_DETAIL_END = "UPDATE security_scans SET sec_scan_end=? WHERE exploit_id=? AND exploit_app=? " \
                                    "AND exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL"\
                                    " AND port_protocol IS NULL)) AND port_number=? AND scan_id=?"
    SELECT_SECURITY_SCANS = "SELECT exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, " \
                            "port_number, sec_scan_start, sec_scan_end, scan_id FROM security_scans" \
                            " INNER JOIN scans ON scan_id=scans.ROWID WHERE exploit_app=? AND node_id=? AND node_ip=? "\
                            "AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? "\
                            "AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?"
    CLEAR_SECURITY_SCANS = "DELETE FROM security_scans WHERE sec_scan_start >= sec_scan_end OR sec_scan_start IS NULL "\
                           "OR sec_scan_end IS NULL"
    SELECT_SCANS_BY_SEC_SCAN = "SELECT scans.ROWID, protocol, scanner_name, scan_start, scan_end FROM scans " \
                               "LEFT JOIN security_scans ON scans.ROWID = security_scans.scan_id WHERE node_id=? AND " \
                               "node_ip=? AND port_number=? AND (port_protocol=? OR (? IS NULL " \
                               "AND port_protocol IS NULL)) AND exploit_id=? AND exploit_app=? AND exploit_name=?" \
                               "ORDER BY scan_end DESC, scan_start ASC LIMIT {limit} OFFSET {offset}"

    CREATE_VULNERABILITIES_TABLE = "CREATE TABLE IF NOT EXISTS vulnerabilities(scan_id int, node_id int, node_ip int, "\
                                   "port_protocol int, port int, vulnerability_id int, vulnerability_subid int, "\
                                   "cve text, cvss text, output text, time int, primary key(scan_id, node_id, "\
                                   "node_ip, port_protocol, port, vulnerability_subid))"
    SAVE_VULNERABILITY = "INSERT OR REPLACE INTO vulnerabilities (scan_id, node_id, node_ip, port_protocol, port, " \
                         "vulnerability_id, vulnerability_subid, cve, cvss, output, time) " \
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    SELECT_VULNERABILITIES = "SELECT scan_id, node_id, node_ip, port_protocol, port, vulnerability_id, " \
                             "vulnerability_subid, cve, cvss, output, time, ROWID FROM vulnerabilities WHERE node_id=?"\
                             " AND node_ip=? AND port=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL))"\
                             " AND vulnerability_id=? AND scan_id=?"

    CREATE_CHANGES_TABLE = "CREATE TABLE IF NOT EXISTS changes(type int, vulnerability_id int, "\
                           "vulnerability_subid int, previous_id int, current_id int, time int, PRIMARY KEY(type, " \
                           "vulnerability_id, vulnerability_subid, previous_id, current_id, time))"
    SAVE_CHANGE = "INSERT OR REPLACE INTO changes(type, vulnerability_id, vulnerability_subid, previous_id, " \
                  "current_id, time) VALUES (?, ?, ?, ?, ?, ?)"

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

    def get_last_rowid(self):
        return self.execute((self.GET_LAST_ROWID,))[0][0] or None

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

    def _save_node(self, node, scan, scan_id=None):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            tuple

        """
        if not scan_id:
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
        return [self._save_node(node=node, scan=scan, scan_id=scan_id) for node in nodes]

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

    def _get_vulnerabilities(self, port, exploit, scan):
        """
        Returns all nodes from local storage

        Args:
            pasttime (int):
            timestamp (int):
            scan (Scan):

        Returns:
            tuple

        """
        iana = self._protocol_to_iana(port.transport_protocol)
        scan_id = self.get_scan_id(scan)
        return self.SELECT_VULNERABILITIES, (port.node.id, str(port.node.ip), port.number, iana, iana, exploit.id,
                                             scan_id)

    def _save_port(self, port, scan, scan_id=None):
        """
        Query for saving port scan into database

        Args:
            port (Port): port to save into storage

        Returns:
            tuple

        """
        if not scan_id:
            scan_id = self.get_scan_id(scan)
        return self.SAVE_PORT_QUERY, (scan_id, port.node.id, str(port.node.ip), port.number,
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
        return [self._save_port(port=port, scan=scan, scan_id=scan_id) for port in ports]

    def _get_ports(self, pasttime, scan):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            pasttime(int)
            scan (Scan):

        Returns:
            tuple

        """
        timestamp = time.time() - pasttime
        iana = self._protocol_to_iana(scan.protocol)

        return self.SELECT_PORTS, (timestamp, iana, iana, scan.scanner)

    def _get_scan_nodes(self, scan):
        """
        Query for port scan detail for given scan

        Args:
            scan (Scan):

        Returns:
            tuple

        """
        scan_id = self.get_scan_id(scan)
        return self.SELECT_SCAN_NODES, (scan_id, )

    def _get_scans_by_node(self, node, scan, limit=2, offset=0):
        """
        Query for port scan detail for given scan

        Args:
            scan (Scan):

        Returns:
            tuple

        """
        iana = self._protocol_to_iana(scan.protocol)
        return self.SELECT_SCANS_BY_NODE.format(limit=limit, offset=offset), (node.id, str(node.ip), iana, iana,
                                                                              scan.scanner)

    def _get_scans_by_security_scan(self, exploit, port, limit=2, offset=0):
        """
        Query for port scan detail for given scan

        Args:
            scan (Scan):

        Returns:
            tuple

        """
        iana = self._protocol_to_iana(port.transport_protocol)
        return self.SELECT_SCANS_BY_SEC_SCAN.format(limit=limit, offset=offset), (port.node.id, str(port.node.ip),
                                                                                  port.number, iana, iana, exploit.id,
                                                                                  exploit.app, exploit.name)

    def _save_security_scan(self, exploit, port, scan):
        """
        Queries for saving scan into database

        Args:
            exploit (Exploit): needs some exploit details to save into storage
            port (Port): needs some port details to save into storage
            scan (Scan):

        Returns:
            list

        """
        log.debug("Saving scan details: scan_start(%s), scan_end(%s), exploit_id(%s), node_id(%s), node(%s), port(%s)",
                  port.scan.start, port.scan.end, exploit.id, port.node.id, str(port.node), str(port))
        queries = []
        iana = self._protocol_to_iana(port.transport_protocol)
        scan_id = self.get_scan_id(scan)

        queries.append((self.SAVE_SECURITY_SCAN_DETAIL, (scan_id, exploit.id, exploit.app, exploit.name, port.node.id,
                                                         str(port.node.ip), iana, port.number)))

        if port.scan.start:
            queries.append((self.SAVE_SECURITY_SCAN_DETAIL_START, (port.scan.start, exploit.id, exploit.app,
                                                                   exploit.name, port.node.id, str(port.node.ip), iana,
                                                                   iana, port.number, scan_id)))

        if port.scan.end:
            queries.append((self.SAVE_SECURITY_SCAN_DETAIL_END, (port.scan.end, exploit.id, exploit.app, exploit.name,
                                                                 port.node.id, str(port.node.ip), iana, iana,
                                                                 port.number, scan_id)))
        return queries

    def _save_security_scans(self, exploits, port, scan):
        """
        Queries for saving scans into database

        Args:
            exploits (list): List of Exploits
            port (Port):

        Returns:
            list
 .

        """
        return [query for exploit in exploits for query in self._save_security_scan(exploit=exploit, port=port,
                                                                                    scan=scan)]

    def _get_security_scan_info(self, port, app, scan):
        """
        Query for scan detail for provided port and app

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        iana = self._protocol_to_iana(port.transport_protocol)
        scan_iana = self._protocol_to_iana(scan.protocol)
        return self.SELECT_SECURITY_SCANS, (app, port.node.id, str(port.node.ip), iana, iana, port.number, scan_iana,
                                            scan_iana, scan.scanner)

    def _save_change(self, change):
        """
        Query for saving changes between scans

        Args:
            change: VulnerabilityChange

        Returns:
            tuple

        """
        return self.SAVE_CHANGE, (change.type.value, change.vulnerability_id, change.vulnerability_subid,
                                  change.previous_finding.rowid if change.previous_finding else None,
                                  change.current_finding.rowid if change.current_finding else None, change.time)

    def _save_changes(self, changes):
        """
        Queries for saving multiple changes into database

        Args:
            changes (list):

        Returns:
            list

        """
        return [self._save_change(change) for change in changes]

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
                   (self.CREATE_NODES_TABLE,),
                   (self.CREATE_VULNERABILITIES_TABLE,),
                   (self.CREATE_CHANGES_TABLE,)]

        return queries

    def _get_ports_by_node_and_scan(self, node, scan):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name
            protocol (TransportProtocol):

        Returns:
            tuple

        """
        scan_id = self.get_scan_id(scan)
        return self.SELECT_PORTS_BY_NODE_AND_SCAN, (node.id, str(node.ip), scan_id)

    def _get_ports_by_nodes(self, nodes, timestamp, protocol=None, portdetection_only=False):
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

        if portdetection_only is True:
            query = self.SELECT_PORTS_BY_NODES_PORTDETECTION
            parameters.extend((TCPScanner.NAME, UDPScanner.NAME))

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

    def save_node(self, node, scan):
        """
        Save node to database

        Args:
            node (Node):

        Returns:
            None

        """
        return self.execute(self._save_node(node=node, scan=scan))

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

    def get_vulnerabilities(self, port, exploit, scan):
        """
        Get nodes from database since timestamp. If timestamp is not given, it's computed basing on pastime.

        Args:
            pasttime (int):
            timestamp (int):

        Returns:
            list - list of nodes
        """
        return [Vulnerability(port=port, exploit=exploit, cve=row[7], cvss=row[8], output=row[9],
                              subid=row[6], vuln_time=row[10], rowid=row[11])
                for row in self.execute(self._get_vulnerabilities(port=port, exploit=exploit, scan=scan))]

    def save_port(self, port, scan):
        """
        Save port to database

        Args:
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_port(port=port, scan=scan))

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

    def get_ports_by_scan_and_node(self, node, scan):
        """
        Get ports from database for given node and scan.

        Args:
            node (Node):
            scan (Scan):

        Returns:
            list - list of Ports

        """
        ports_scans = []

        for row in self.execute(self._get_ports_by_node_and_scan(node=node, scan=scan)):
            storage_port = Port(node=Node(node_id=row[0], ip=ipaddress.ip_address(row[1])),
                                transport_protocol=self._transport_protocol(row[3]), number=row[2])
            ports_scans.append(PortScan(port=storage_port, rowid=row[5], scan=scan, timestamp=row[4]))
        return ports_scans

    def get_nodes_by_scan(self, scan):
        """
        Get nodes from database for given scan.

        Args:
            pasttime (int):

        Returns:
            list - list of Ports

        """
        nodes = []

        for node in self.execute(self._get_scan_nodes(scan=scan)):
            storage_node = Node(node_id=node[0], ip=ipaddress.ip_address(node[1]))
            storage_node.scan = scan
            nodes.append(storage_node)
        return nodes

    def save_security_scan(self, exploit, port, scan):
        """
        Save scan of port by exploit to database

        Args:
            exploit (Exploit):
            port (Port):
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_security_scan(exploit=exploit, port=port, scan=scan))

    def save_security_scans(self, exploits, port, scan):
        """
        Save scans of port to database basing on given exploits

        Args:
            exploits (list):
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_security_scans(exploits=exploits, port=port, scan=scan))

    def get_security_scan_info(self, port, app, scan):
        """
        Get scan info from database

        Args:
            port (Port):
            app (str):

        Returns:
            tuple

        """
        return_value = []

        for row in self.execute(self._get_security_scan_info(port=port, app=app, scan=scan)):
            return_value.append(SecurityScan(port=Port(node=Node(node_id=row[3], ip=ipaddress.ip_address(row[4])),
                                                       number=row[6],
                                                       transport_protocol=self._transport_protocol(row[5])),
                                             exploit=Exploit(exploit_id=row[0], name=row[2], app=row[1]),
                                             scan_start=row[7], scan_end=row[8], scan=self.get_scan(row[9])))

        return return_value

    def save_changes(self, changes):
        """
        Save changes to database

        Args:
            changes (list):

        Returns:
            None

        """
        return self.execute(self._save_changes(changes=changes))

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

    def get_ports_by_nodes(self, nodes, pasttime=0, timestamp=None, protocol=None, portdetection_only=False):
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

        for row in self.execute(self._get_ports_by_nodes(nodes=nodes, timestamp=timestamp, protocol=protocol,
                                                         portdetection_only=portdetection_only)):
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
        return self.UPDATE_SCAN_END_QUERY, (scan.end, scan.rowid)

    def _get_scans(self, protocol, scanner_name, limit=2, offset=0):
        iana = self._protocol_to_iana(protocol)
        return self.SELECT_SCANS.format(limit=limit, offset=offset), (iana, iana, scanner_name)

    def _get_scan(self, scan):
        iana = self._protocol_to_iana(scan.protocol)
        return self.SELECT_SCAN, (iana, iana, scan.scanner, scan.start)

    def _get_scan_by_id(self, scan_id):
        return self.SELECT_SCAN_BY_ID, (scan_id, )

    def save_scan(self, scan):
        """
        Save scan into storage

        Args:
            scan (Scan):

        Returns:

        """
        self.execute(self._save_scan(scan=scan))
        scan.rowid = self.get_last_rowid()
        return scan

    def update_scan(self, scan):
        """
        Update scan in storage

        Args:
            scan (Scan):

        Returns:

        """
        return self.execute(self._update_scan(scan=scan))

    def get_scan(self, scan_id):
        rows = self.execute((self.SELECT_SCAN_BY_ID, (scan_id, )))

        if not rows:
            return None
        return self._scan_from_row(rows[0])

    def get_scan_id(self, scan):
        """
        Get scan_id

        Args:
            scan (Scan):

        Returns:
            int

        """
        if scan.rowid:
            return scan.rowid

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
        return[self._scan_from_row(row) for row in self.execute(self._get_scans(protocol=protocol, limit=amount,
                                                                                offset=0, scanner_name=scanner_name))]

    def get_scans_by_node(self, node, scan):
        """
        Obtain scans from storage based on given node

        Args:
            protocol (TransportProtocol):
            scan (Scan):

        Returns:
            list - list of scans

        """
        return [self._scan_from_row(row) for row in self.execute(self._get_scans_by_node(node=node, scan=scan))]

    def get_scans_by_security_scan(self, exploit, port):
        """
        Obtain scans from storage based on given node

        Args:
            protocol (TransportProtocol):
            scanner_name (str):
            amount (int):

        Returns:
            list - list of scans

        """
        return [self._scan_from_row(row) for row in self.execute(self._get_scans_by_security_scan(port=port,
                                                                                                  exploit=exploit))]

    def get_scan_by_id(self, scan_id):
        """
        Obtain scan from storage

        Args:
            scan_id (int):

        Returns:
            Scan

        """
        result = self.execute(self._get_scan_by_id(scan_id))
        if not result:
            return None

        return self._scan_from_row(result[0])

    def _save_vulnerabilities(self, vulnerabilities, scan):
        """
        Save vulnarabilities into local storage

        Args:
            vulnerabilities (list): list of Vulnerability
            scan (Scan):

        Returns:
            None

        """
        scan_id = self.get_scan_id(scan)
        queries = [(self.SAVE_VULNERABILITY, (scan_id, vuln.port.node.id, str(vuln.port.node.ip),
                                              self._protocol_to_iana(vuln.port.transport_protocol), vuln.port.number,
                                              vuln.exploit.id, vuln.subid, vuln.cve, vuln.cvss, vuln.output,
                                              vuln.time))
                   for vuln in vulnerabilities]
        return queries

    def save_vulnerabilities(self, vulnerabilities, scan):
        """
        Save vulnarabilities into local storage

        Args:
            vulnerabilities (list): list of Vulnerability
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_vulnerabilities(vulnerabilities=vulnerabilities, scan=scan))

    def _scan_from_row(self, row):
        return Scan(start=row[3], end=row[4], protocol=self._transport_protocol(row[1]), scanner=row[2], rowid=row[0])
