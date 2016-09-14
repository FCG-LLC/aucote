"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3

from sqlite3 import Connection

from structs import Node
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
            self.cursor.execute("INSERT INTO nodes (id, name, ip) VALUES (?, ?, ?)", (node.id, str(node.name), str(node.ip)))
        except sqlite3.DatabaseError:
            self.cursor.execute("CREATE TABLE nodes(id int, name text, ip text)")
            self.conn.commit()

            self.save_node(node, commit)

        if commit:
            self.conn.commit()

    def save_nodes(self, nodes):
        """
        Save nodes into local storage
        Args:
            nodes (list):

        Returns:
            None

        """
        for node in nodes:
            self.save_node(node, False)

        self.conn.commit()

    def get_nodes(self):
        nodes = []
        for node in self.cursor.execute("SELECT * FROM nodes").fetchall():
            nodes.append(Node(id=node[0], name=node[1], ip=ipaddress.ip_address(node[2])))
        return nodes