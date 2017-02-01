"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3
import time
import logging as log

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, StorageQuery
from utils.database_interface import DbInterface


class Storage(DbInterface):
    """
    This class provides local storage funxtionality

    """

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

    @staticmethod
    def save_node(node):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            set

        """
        return "INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (node.id, str(node.ip), time.time())

    @staticmethod
    def save_nodes(nodes):
        """
        Saves nodes into local storage

        Args:
            nodes (list):

        Returns:
            list

        """
        queries = [("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)",
                    (node.id, str(node.ip), time.time())) for node in nodes]

        log.debug("Saving nodes")
        return queries

    @staticmethod
    def get_nodes(pasttime=0):
        """
        Returns all nodes from local storage

        Returns:
            set

        """
        timestamp = time.time() - pasttime

        return "SELECT * FROM nodes where time > ?", (timestamp,)

    @staticmethod
    def save_port(port):
        """
        Saves port to local storage

        Args:
            port (Port): port to save into storage
            commit (bool): commit to database switch
            lock (bool): define if thread should be locked

        Returns:
            set

        """
        return "INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)", (
            port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana, time.time())

    @staticmethod
    def save_ports(ports):
        """
        Saves ports into local storage

        Args:
            ports (list):

        Returns:
            list

        """
        queries = [("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                    (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana,
                     time.time())) for port in ports]

        return queries

    @staticmethod
    def get_ports(pasttime):
        timestamp = time.time() - pasttime

        return "SELECT * FROM ports where time > ?", (timestamp,)

    @staticmethod
    def save_scan(exploit, port):
        """
        Saves scan information into storage. Create table scans if not exists

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

        queries.append(("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
                        "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
                         port.transport_protocol.iana, port.number)))

        if port.scan.start:
            queries.append(("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
                            "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
                            (port.scan.start, exploit.id, exploit.app, exploit.name, port.node.id,
                             str(port.node.ip), port.transport_protocol.iana, port.number)))

        if port.scan.end:
            queries.append(("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
                            "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
                            (port.scan.end, exploit.id, exploit.app, exploit.name, port.node.id,
                             str(port.node.ip), port.transport_protocol.iana, port.number)))
        return queries

    @staticmethod
    def save_scans(exploits, port):
        """
        Save scan details into local storage

        Args:
            exploits (list): List of Exploits
            port (Port):

        Returns:
            list

        """
        queries = []

        for exploit in exploits:
            queries.append(("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
                            "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
                             port.transport_protocol.iana, port.number)))

            if port.scan.start:
                queries.append(("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
                                "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
                                (port.scan.start, exploit.id, exploit.app, exploit.name, port.node.id,
                                 str(port.node.ip), port.transport_protocol.iana, port.number)))

            if port.scan.end:
                queries.append(("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
                                "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
                                (port.scan.end, exploit.id, exploit.app, exploit.name, port.node.id,
                                 str(port.node.ip), port.transport_protocol.iana, port.number)))

        return queries

    @staticmethod
    def get_scan_info(port, app):
        """
        Gets scan details based on provided port and app name

        Args:
            port (Port):
            app (str): app name

        Returns:
            list - list of dictionaries with keys: exploit, port, scan_start, scan_end

        """
        return "SELECT * FROM scans WHERE exploit_app = ? AND node_id = ? AND node_ip = ? AND port_protocol = ? " \
               "AND port_number = ?", (app, port.node.id, str(port.node.ip), port.transport_protocol.iana, port.number)

    @staticmethod
    def clear_scan_details():
        """
        Remove unfinished scans from database

        Returns:
            set

        """
        log.debug('Cleaning scan details')
        return "DELETE FROM scans WHERE scan_start >= scan_end OR scan_start IS NULL OR SCAN_END IS NULL",

    @staticmethod
    def create_tables():
        """
        Create tables for local storage

        Returns:
            list

        """
        queries = []
        queries.append(("CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, exploit_name text, "
                             "node_id int, node_ip text, port_protocol int, port_number int, scan_start float, "
                             "scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, "
                             "port_number))",))

        queries.append(("CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, time int,"
                             "primary key (id, ip, port, protocol))",))

        queries.append(("CREATE TABLE IF NOT EXISTS nodes(id int, ip text, time int, primary key (id, ip))",))

        return queries
