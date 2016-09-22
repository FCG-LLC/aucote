"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3
import time

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol
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
        self.conn = sqlite3.connect(self.filename)
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

    def save_node(self, node, commit=True):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            None

        """

        try:
            self.cursor.execute("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)",
                                (node.id, str(node.ip), time.time()))
        except sqlite3.DatabaseError:
            self.cursor.execute("CREATE TABLE nodes(id int, ip text, time int, primary key (id, ip))")
            self.conn.commit()

            self.save_node(node, commit)

        if commit:
            self.conn.commit()

    def save_nodes(self, nodes):
        """
        Saves nodes into local storage

        Args:
            nodes (list):

        Returns:
            None

        """
        for node in nodes:
            self.save_node(node, False)

        self.conn.commit()

    def get_nodes(self, pasttime=0):
        """
        Returns all nodes from local storage

        Returns:
            list

        """
        timestamp = time.time() - pasttime

        nodes = []
        try:
            for node in self.cursor.execute("SELECT * FROM nodes where time > ?", (timestamp,)).fetchall():
                nodes.append(Node(node_id=node[0], ip=ipaddress.ip_address(node[1])))
            return nodes
        except sqlite3.DatabaseError:
            return []

    def save_port(self, port, commit=True):
        """
        Saves port to local storage

        Args:
            port (Port): port to save into storage
            commit (bool): commit to database switch

        Returns:
            None

        """
        try:
            self.cursor.execute("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                                (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana,
                                 time.time()))
        except sqlite3.DatabaseError:
            self.cursor.execute("CREATE TABLE ports (id int, ip text, port int, protocol int, time int,"
                                "primary key (id, ip, port, protocol))")
            self.conn.commit()

            self.save_port(port, commit)

        if commit:
            self.conn.commit()

    def save_ports(self, ports):
        """
        Saves ports into local storage

        Args:
            ports (list):

        Returns:
            None

        """
        for port in ports:
            self.save_port(port, False)

        self.conn.commit()

    def get_ports(self, pasttime=900):
        """
        Returns all ports from local storage

        Returns:
            list

        """
        timestamp = time.time() - pasttime

        ports = []
        try:
            for port in self.cursor.execute("SELECT * FROM ports where time > ?", (timestamp,)).fetchall():
                ports.append(Port(node=Node(node_id=port[0], ip=ipaddress.ip_address(port[1])), number=port[2],
                                  transport_protocol=TransportProtocol.from_iana(port[3])))
            return ports
        except sqlite3.DatabaseError:
            return []

    def save_scan(self, exploit, port, scan_start=None, scan_end=None, commit=True):
        """
        Saves scan informations into storage. Create table scans if not exists

        Args:
            exploit (Exploit): needs some exploit details to save into storage
            port (Port): needs some port details to save into storage
            scan_start (float): timestamp of scan start
            scan_end (float): timestamp of scan finish
            commit (bool): commit changes

        Returns:
            None

        """

        try:
            self.cursor.execute("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
                                "port_protocol, port_number)"
                                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                                (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
                                 port.transport_protocol.iana, port.number))

            if scan_start:
                self.cursor.execute("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
                                    "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
                                    (scan_start, exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
                                     port.transport_protocol.iana, port.number))

            if scan_end:
                self.cursor.execute("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
                                    "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
                                    (scan_end, exploit.id, exploit.app, exploit.name, port.node.id,
                                     str(port.node.ip), port.transport_protocol.iana, port.number))

        except sqlite3.DatabaseError:
            self.cursor.execute("CREATE TABLE scans (exploit_id int, exploit_app text, exploit_name text, node_id int,"
                                "node_ip text, port_protocol int, port_number int, scan_start float, scan_end float,"
                                "PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, port_number))")
            self.conn.commit()

            self.save_scan(exploit=exploit, port=port, scan_start=scan_start, scan_end=scan_end, commit=commit)

        if commit:
            self.conn.commit()

    def get_scan_info(self, port, app):
        """
        Gets scan details based on provided port and app name

        Args:
            port (Port):
            app (str): app name

        Returns:
            list - list of dictionaries with keys: exploit, port, scan_start, scan_end

        """
        return_value = []

        try:
            for row in self.cursor.execute("SELECT * FROM scans WHERE exploit_app = ? AND node_id = ? AND node_ip = ? "
                                           "AND port_protocol = ? AND port_number = ?",
                                           [app, port.node.id, str(port.node.ip), port.transport_protocol.iana,
                                            port.number]):
                return_value.append({
                    "exploit": Exploit(exploit_id=row[0]),
                    "port": Port(node=Node(node_id=row[3], ip=ipaddress.ip_address(row[4])), number=row[6],
                                 transport_protocol=TransportProtocol.from_iana(row[5])),
                    "scan_start": row[7],
                    "scan_end": row[8],
                })

            return return_value

        except sqlite3.DatabaseError:
            return []
