import ipaddress
from unittest import TestCase

from sqlite3 import Connection, DatabaseError

from sqlite3 import connect
from unittest.mock import MagicMock

from structs import Node, Port, TransportProtocol
from utils.storage import Storage


class StorageTest(TestCase):

    def setUp(self):
        self.storage = Storage(":memory:")

    def test_init(self):
        self.assertEqual(self.storage.filename, ":memory:")

    def test_context_manager(self):
        with self.storage as storage:
            self.assertTrue(True)

    def test_connect(self):
        self.storage.connect()

        self.assertIsInstance(self.storage.conn, Connection)

    def test_close(self):
        self.storage.conn = connect(":memory:")
        self.storage.close()

        self.assertEqual(self.storage.conn, None)

    def test_save_node(self):
        node = Node(id=1, ip=ipaddress.ip_address('127.0.0.1'), name='localhost')
        with self.storage as storage:
            storage.save_node(node)

            expected = storage.cursor.execute("SELECT * FROM nodes").fetchone()

            self.assertEqual(expected[0], 1)
            self.assertEqual(expected[1], 'localhost')
            self.assertEqual(expected[2], '127.0.0.1')

    def test_save_nodes(self):
        nodes = [Node(id=1, ip=ipaddress.ip_address('127.0.0.1'), name='localhost'),
                 Node(id=2, ip=ipaddress.ip_address('127.0.0.2'), name='localhost'),
                 Node(id=3, ip=ipaddress.ip_address('127.0.0.3'), name='localhost')]

        with self.storage as storage:
            storage.save_nodes(nodes)

            expected = storage.cursor.execute("SELECT * FROM nodes").fetchall()

            self.assertEqual(expected[0][0], 1)
            self.assertEqual(expected[0][1], 'localhost')
            self.assertEqual(expected[0][2], '127.0.0.1')

            self.assertEqual(expected[1][0], 2)
            self.assertEqual(expected[1][1], 'localhost')
            self.assertEqual(expected[1][2], '127.0.0.2')

            self.assertEqual(expected[2][0], 3)
            self.assertEqual(expected[2][1], 'localhost')
            self.assertEqual(expected[2][2], '127.0.0.3')

    def test_get_nodes(self):
        nodes = [Node(id=1, ip=ipaddress.ip_address('127.0.0.1'), name='localhost'),
                 Node(id=2, ip=ipaddress.ip_address('127.0.0.2'), name='localhost'),
                 Node(id=3, ip=ipaddress.ip_address('127.0.0.3'), name='localhost')]

        with self.storage as storage:
            storage.save_nodes(nodes)

            expected = storage.get_nodes()

            for i in range(3):
                self.assertEqual(expected[i].ip, nodes[i].ip)
                self.assertEqual(expected[i].name, nodes[i].name)
                self.assertEqual(expected[i].id, nodes[i].id)

    def test_get_nodes_exception(self):
        self.storage._cursor = MagicMock()
        self.storage._cursor.execute = MagicMock(side_effect=DatabaseError)

        result = self.storage.get_nodes()
        self.assertEqual(result, [])

    def test_save_port(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), id=1), transport_protocol=TransportProtocol.TCP,
                    number=1)
        with Storage(":memory:") as storage:
            storage.save_port(port)

            expected = storage.cursor.execute("SELECT * FROM ports").fetchone()

        self.assertEqual(expected[0], 1)
        self.assertEqual(expected[1], '127.0.0.1')
        self.assertEqual(expected[2], 1)
        self.assertEqual(expected[3], TransportProtocol.TCP.iana)
