"""
This file contains class for storage temporary information like last date of scanning port
"""
import sqlite3
import time
import logging as log
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

    def __init__(self, filename="storage.sqlite3"):

        """
        Init storage

        Args:
            filename (str): filename of provided storage

        """

        self.filename = filename
        self.conn = None
        self._cursor = None

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

    def save_node(self, node):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            tuple

        """
        return self.SAVE_NODE_QUERY, (node.id, str(node.ip), time.time())

    def save_nodes(self, nodes):
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

    def get_nodes(self, pasttime, timestamp):
        """
        Returns all nodes from local storage

        Returns:
            tuple

        """
        if timestamp is None:
            timestamp = time.time() - pasttime
        return "SELECT * FROM nodes where time > ?", (timestamp,)

    def save_port(self, port):
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

    def save_ports(self, ports):
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

    def get_ports(self, pasttime, ):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        timestamp = time.time() - pasttime

        return "SELECT * FROM ports where time > ?", (timestamp,)

    def save_scan(self, exploit, port):
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

    def save_scans(self, exploits, port):
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

    def get_scan_info(self, port, app):
        """
        Query for scan detail for provided port and app

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """
        return "SELECT * FROM scans WHERE exploit_app = ? AND node_id = ? AND node_ip = ? AND port_protocol = ? " \
               "AND port_number = ?", (app, port.node.id, str(port.node.ip), port.transport_protocol.iana, port.number)

    def clear_scan_details(self):
        """
        Query for cleaning table

        Returns:
            tuple

        """
        log.debug('Cleaning scan details')
        return "DELETE FROM scans WHERE scan_start >= scan_end OR scan_start IS NULL OR SCAN_END IS NULL",

    def create_tables(self):
        """
        List of queries for table creation

        Returns:
            list

        """
        queries = [("CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, exploit_name text, "
                    "node_id int, node_ip text, port_protocol int, port_number int, scan_start float, "
                    "scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, "
                    "port_number))",),

                   ("CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, time int,"
                    "primary key (id, ip, port, protocol))",),

                   ("CREATE TABLE IF NOT EXISTS nodes(id int, ip text, time int, primary key (id, ip))",)]

        return queries

    def get_ports_by_node(self, node, timestamp=None):
        """
        Query for port scan detail from scans from pasttime ago

        Args:
            port (Port):
            app (str): app name

        Returns:
            tuple

        """

        return "SELECT * FROM ports where id=? AND ip=? AND time > ?", (node.id, str(node.ip), timestamp,)

    def get_ports_by_nodes(self, nodes, timestamp):
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

        return "SELECT * FROM ports where ({where}) AND time > ?".format(where=where), parameters
