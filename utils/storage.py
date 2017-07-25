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
    SAVE_NODE_QUERY = "INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)"
    SAVE_PORT_QUERY = "INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)"
    SAVE_SCAN_DETAIL = "INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip," \
                       "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)"
    SAVE_SCAN_DETAIL_START = "UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND " \
                             "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?"
    SAVE_SCAN_DETAIL_END = "UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND " \
                           "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?"
    SELECT_NODES = "SELECT id, ip, time FROM nodes where time > ?"
    SELECT_PORTS = "SELECT id, ip, port, protocol, time FROM ports where time > ?"
    SELECT_SCANS = "SELECT exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, port_number, " \
                   "scan_start, scan_end FROM scans WHERE exploit_app = ? AND node_id = ? AND node_ip = ? " \
                   "AND port_protocol = ? AND port_number = ?"
    SELECT_PORTS_BY_NODE = "SELECT id, ip, port, protocol, time FROM ports where id=? AND ip=? AND time > ?"
    SELECT_PORTS_BY_NODES = "SELECT id, ip, port, protocol, time FROM ports where ({where}) AND time > ?"
    CLEAR_SCANS = "DELETE FROM scans WHERE scan_start >= scan_end OR scan_start IS NULL OR SCAN_END IS NULL"
    CREATE_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, exploit_name text, " \
                         "node_id int, node_ip text, port_protocol int, port_number int, scan_start float, " \
                         "scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, port_number))"
    CREATE_PORTS_TABLE = "CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, time int," \
                         "primary key (id, ip, port, protocol))"
    CREATE_NODES_TABLE = "CREATE TABLE IF NOT EXISTS nodes(id int, ip text, time int, primary key (id, ip))"

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
        self.execute(self._clear_scan_details())

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

    def _save_node(self, node):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            tuple

        """
        return self.SAVE_NODE_QUERY, (node.id, str(node.ip), time.time())

    def _save_nodes(self, nodes):
        """
        Saves nodes into local storage

        Args:
            nodes (list):

        Returns:
            list

        """
        queries = [(self.SAVE_NODE_QUERY, (node.id, str(node.ip), time.time())) for node in nodes]

        log.debug("Saving nodes")
        return queries

    def _get_nodes(self, pasttime, timestamp):
        """
        Returns all nodes from local storage

        Returns:
            tuple

        """
        if timestamp is None:
            timestamp = time.time() - pasttime
        return self.SELECT_NODES, (timestamp,)

    def _save_port(self, port):
        """
        Query for saving port scan into database

        Args:
            port (Port): port to save into storage
            commit (bool): commit to database switch
            lock (bool): define if thread should be locked

        Returns:
            tuple

        """
        return self.SAVE_PORT_QUERY, (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana,
                                      time.time())

    def _save_ports(self, ports):
        """
        Queries for saving ports scans into database

        Args:
            ports (list):

        Returns:
            list

        """
        queries = [(self.SAVE_PORT_QUERY, (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana,
                                           time.time())) for port in ports]

        return queries

    def _get_ports(self, pasttime):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        timestamp = time.time() - pasttime

        return self.SELECT_PORTS, (timestamp,)

    def _save_scan(self, exploit, port):
        """
        Queries for saving scan into database

        Args:
            exploit (Exploit): needs some exploit details to save into storage
            port (Port): needs some port details to save into storage
            commit (bool): commit changes
            lock (bool): define if thread should be locked

        Returns:
            list

        """

        log.debug("Saving scan details: scan_start(%s), scan_end(%s), exploit_id(%s), node_id(%s), node(%s), port(%s)",
                  port.scan.start, port.scan.end, exploit.id, port.node.id, str(port.node), str(port))
        queries = []

        queries.append((self.SAVE_SCAN_DETAIL, (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
                                                port.transport_protocol.iana, port.number)))

        if port.scan.start:
            queries.append((self.SAVE_SCAN_DETAIL_START, (port.scan.start, exploit.id, exploit.app, exploit.name,
                                                          port.node.id, str(port.node.ip), port.transport_protocol.iana,
                                                          port.number)))

        if port.scan.end:
            queries.append((self.SAVE_SCAN_DETAIL_END, (port.scan.end, exploit.id, exploit.app, exploit.name,
                                                        port.node.id, str(port.node.ip), port.transport_protocol.iana,
                                                        port.number)))
        return queries

    def _save_scans(self, exploits, port):
        """
        Queries for saving scans into database

        Args:
            exploits (list): List of Exploits
            port (Port):

        Returns:
            list

        """
        queries = []

        for exploit in exploits:
            queries.append((self.SAVE_SCAN_DETAIL, (exploit.id, exploit.app, exploit.name, port.node.id,
                                                    str(port.node.ip), port.transport_protocol.iana, port.number)))

            if port.scan.start:
                queries.append((self.SAVE_SCAN_DETAIL_START, (port.scan.start, exploit.id, exploit.app, exploit.name,
                                                              port.node.id, str(port.node.ip),
                                                              port.transport_protocol.iana, port.number)))

            if port.scan.end:
                queries.append((self.SAVE_SCAN_DETAIL_END, (port.scan.end, exploit.id, exploit.app, exploit.name,
                                                            port.node.id, str(port.node.ip),
                                                            port.transport_protocol.iana, port.number)))

        return queries

    def _get_scan_info(self, port, app):
        """
        Query for scan detail for provided port and app

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        return self.SELECT_SCANS, (app, port.node.id, str(port.node.ip), port.transport_protocol.iana, port.number)

    def _clear_scan_details(self):
        """
        Query for cleaning table

        Returns:
            tuple

        """
        log.debug('Cleaning scan details')
        return self.CLEAR_SCANS,

    def _create_tables(self):
        """
        List of queries for table creation

        Returns:
            list

        """
        queries = [(self.CREATE_SCANS_TABLE,),
                   (self.CREATE_PORTS_TABLE,),
                   (self.CREATE_NODES_TABLE,)]

        return queries

    def _get_ports_by_node(self, node, timestamp):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """

        return self.SELECT_PORTS_BY_NODE, (node.id, str(node.ip), timestamp,)

    def _get_ports_by_nodes(self, nodes, timestamp):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        parameters = []
        for node in nodes:
            parameters.extend((node.id, str(node.ip)))

        parameters.append(timestamp)

        where = 'OR'.join([' (id=? AND ip=?) '] * len(nodes))

        return self.SELECT_PORTS_BY_NODES.format(where=where), parameters

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
            log.debug("executing query: %s", query[0])
            return self.cursor.execute(*query).fetchall()

        self.conn.commit()

    def save_node(self, node):
        """
        Save node to database

        Args:
            node (Node):

        Returns:
            None

        """
        return self.execute(self._save_node(node=node))

    def save_nodes(self, nodes):
        """
        Save nodes to database

        Args:
            nodes (lst):

        Returns:
            None

        """
        return self.execute(self._save_nodes(nodes=nodes))

    def get_nodes(self, pasttime=0, timestamp=None):
        """
        Get nodes from database since timestamp. If timestamp is not given, it's computed basing on pastime.

        Args:
            pasttime (int):
            timestamp (int):

        Returns:
            list - list of nodes
        """
        nodes = []

        for node in self.execute(self._get_nodes(pasttime=pasttime, timestamp=timestamp)):
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

    def save_ports(self, ports):
        """
        Save ports to database

        Args:
            ports (list):

        Returns:
            None

        """
        return self.execute(self._save_ports(ports=ports))

    def get_ports(self, pasttime=900):
        """
        Get ports from database from pasttime.

        Args:
            pasttime (int):

        Returns:
            list - list of Ports

        """
        ports = []

        for port in self.execute(self._get_ports(pasttime=pasttime)):
            ports.append(Port(node=Node(node_id=port[0], ip=ipaddress.ip_address(port[1])), number=port[2],
                              transport_protocol=TransportProtocol.from_iana(port[3])))
        return ports

    def save_scan(self, exploit, port):
        """
        Save scan of port by exploit to database

        Args:
            exploit (Exploit):
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_scan(exploit=exploit, port=port))

    def save_scans(self, exploits, port):
        """
        Save scans of port to database basing on given exploits

        Args:
            exploits (list):
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_scans(exploits=exploits, port=port))

    def get_scan_info(self, port, app):
        """
        Get scan info from database

        Args:
            port (Port):
            app (str):

        Returns:
            tuple

        """
        return_value = []

        for row in self.execute(self._get_scan_info(port=port, app=app)):
            return_value.append({
                "exploit": Exploit(exploit_id=row[0]),
                "port": Port(node=Node(node_id=row[3], ip=ipaddress.ip_address(row[4])), number=row[6],
                             transport_protocol=TransportProtocol.from_iana(row[5])),
                "scan_start": row[7] or 0.,
                "scan_end": row[8] or 0.,
                "exploit_name": row[2]
            })

        return return_value

    def clear_scan_details(self):
        """
        Clear broken scan details

        Returns:
            None

        """
        return self.execute(self._clear_scan_details())

    def create_tables(self):
        """
        Create tables in storage

        Returns:
            None

        """
        return self.execute(self._create_tables())

    def get_ports_by_node(self, node, pasttime=0, timestamp=None):
        """
        Get open ports of node since timestamp or from pasttime if timestamp is not given.

        Args:
            node (Node):
            pasttime (int):
            timestamp (int):

        Returns:
            list - list of Nodes

        """
        ports = []
        if timestamp is None:
            timestamp = time.time() - pasttime

        for row in self.execute(self._get_ports_by_node(node=node, timestamp=timestamp)):
            port = Port(node=node, number=row[2], transport_protocol=TransportProtocol.from_iana(row[3]))
            port.scan = Scan(start=port.node.scan.start)
            ports.append(port)

        return ports

    def get_ports_by_nodes(self, nodes, pasttime=0, timestamp=None):
        """
        Get open ports of nodes since timestamp or from pasttime if timestamp is not given.

        Args:
            nodes (list):
            pasttime (int):
            timestamp (int):

        Returns:
            list - list of Ports

        """
        ports = []

        if not nodes:
            return []

        if timestamp is None:
            timestamp = time.time() - pasttime

        for row in self.execute(self._get_ports_by_nodes(nodes=nodes, timestamp=timestamp)):
            node = nodes[nodes.index(Node(node_id=row[0], ip=ipaddress.ip_address(row[1])))]
            port = Port(node=node, number=row[2], transport_protocol=TransportProtocol.from_iana(row[3]))
            port.scan = Scan(start=port.node.scan.start)
            ports.append(port)

        return ports
