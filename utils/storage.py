"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3
import time

from sqlite3 import Connection

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
        assert isinstance(self.conn, Connection)
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
            self.cursor.execute("INSERT OR REPLACE INTO nodes (id, name, ip, time) VALUES (?, ?, ?, ?)",
                                (node.id, str(node.name), str(node.ip), time.time()))
        except sqlite3.DatabaseError:
            self.cursor.execute("CREATE TABLE nodes(id int, name text, ip text, time int, primary key (id, ip))")
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
                nodes.append(Node(id=node[0], name=node[1], ip=ipaddress.ip_address(node[2])))
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
                ports.append(Port(node=Node(id=port[0], ip=ipaddress.ip_address(port[1])), number=port[2],
                                  transport_protocol=TransportProtocol.from_iana(port[3])))
            return ports
        except sqlite3.DatabaseError:
            return []