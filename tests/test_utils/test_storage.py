import ipaddress
from types import GeneratorType
from unittest import TestCase

from sqlite3 import Connection, DatabaseError, time

from sqlite3 import connect
from unittest.mock import MagicMock, patch, call

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, Scan
from utils.storage import Storage


class StorageTest(TestCase):
    def setUp(self):
        self.storage = Storage(filename=":memory:")

    def test_init(self):
        self.assertEqual(self.storage.filename, ":memory:")

    def test_context_manager(self):
        with self.storage:
            self.assertTrue(True)

    def test_connect(self):
        self.storage.connect()

        self.assertIsInstance(self.storage.conn, Connection)

    def test_close(self):
        self.storage.conn = connect(":memory:")
        self.storage.close()

        self.assertEqual(self.storage.conn, None)

    @patch("time.time", MagicMock(return_value=7))
    def test_save_node(self):
        node = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        result = self.storage.save_node(node)
        expected = ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (1, '127.0.0.1', 7))

        self.assertCountEqual(result, expected)

    @patch("time.time", MagicMock(return_value=17))
    def test_save_nodes(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        result = self.storage.save_nodes(nodes)
        expected = (
            ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (1, '127.0.0.1', 17)),
            ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (2, '127.0.0.2', 17)),
            ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (3, '127.0.0.3', 17)),
        )

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))

    def test_get_nodes(self):
        result = self.storage.get_nodes(pasttime=700, timestamp=None)
        expected = 'SELECT id, ip, time FROM nodes where time > ?', (139300,)
        self.assertEqual(result, expected)

    @patch('time.time', MagicMock(return_value=13))
    def test_save_port(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1),
                    transport_protocol=TransportProtocol.TCP, number=1)

        result = self.storage.save_port(port)

        expected = ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                     (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana, 13))

        self.assertCountEqual(result, expected)

    @patch('time.time', MagicMock(return_value=122))
    def test_save_ports(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        ports = [Port(node=nodes[0], transport_protocol=TransportProtocol.TCP, number=5),
                 Port(node=nodes[1], transport_protocol=TransportProtocol.UDP, number=65),
                 Port(node=nodes[2], transport_protocol=TransportProtocol.ICMP, number=99), ]

        result = self.storage.save_ports(ports)

        expected = [
            ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
             (1, '127.0.0.1', 5, 6, 122)),
            ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
             (2, '127.0.0.2', 65, 17, 122)),
            ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
             (3, '127.0.0.3', 99, 1, 122)),
        ]

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))

    def test_get_ports(self):
        result = self.storage.get_ports(700)
        expected = 'SELECT id, ip, port, protocol, time FROM ports where time > ?', (139300,)
        self.assertEqual(result, expected)

    def test_save_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan)
        result = self.storage.save_scan(exploit=exploit, port=port)

        expected = [
            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
               port.transport_protocol.iana, port.number)),
            ("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
              (port.scan.start, exploit.id, exploit.app, exploit.name, port.node.id,
               str(port.node.ip), port.transport_protocol.iana, port.number))
        ]

        self.assertCountEqual(result[0], expected[0])
        self.assertCountEqual(result[1], expected[1])

    def test_save_scans(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        exploit_2 = Exploit(exploit_id=2)
        exploit_2.name = 'test_name_2'
        exploit_2.app = 'test_app_2'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        port.scan = Scan(start=3, end=45)
        result = self.storage.save_scans(exploits=[exploit, exploit_2], port=port)

        expected = [
            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
             "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
             (14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 12)),

            ("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
             (3, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 12)),

            ("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
             (45, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 12)),

            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
             "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
             (2, 'test_app_2', 'test_name_2', 3, '127.0.0.1', 6, 12)),

            ("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
             (3, 2, 'test_app_2', 'test_name_2', 3, '127.0.0.1', 6, 12)),

            ("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
             (45, 2, 'test_app_2', 'test_name_2', 3, '127.0.0.1', 6, 12))
        ]

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    def test_save_scan_without_changing_start_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan, end=start_scan)
        result = self.storage.save_scan(exploit=exploit, port=port)

        expected = [
            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
               port.transport_protocol.iana, port.number)),
            ("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
              (port.scan.start, exploit.id, exploit.app, exploit.name, port.node.id,
               str(port.node.ip), port.transport_protocol.iana, port.number)),
            ("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
              (port.scan.end, exploit.id, exploit.app, exploit.name, port.node.id,
               str(port.node.ip), port.transport_protocol.iana, port.number))
        ]

        self.assertCountEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))
    def test_get_scan_info(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)


        result = self.storage.get_scan_info(port=port, app='test_app')
        expected = ('SELECT exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, port_number, '
                    'scan_start, scan_end FROM scans WHERE exploit_app = ? AND node_id = ? AND node_ip = ? '
                    'AND port_protocol = ? AND port_number = ?', ('test_app', 3, '127.0.0.1', 6, 12))

        self.assertCountEqual(result, expected)

    def test_create_table(self):
        result = self.storage.create_tables()
        expected = [
            ("CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, exploit_name text, "
              "node_id int, node_ip text, port_protocol int, port_number int, scan_start float, "
              "scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, port_number))",),

            ("CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, time int,"
              "primary key (id, ip, port, protocol))",),

            ("CREATE TABLE IF NOT EXISTS nodes(id int, ip text, time int, primary key (id, ip))",),
        ]

        self.assertCountEqual(result, expected)

    def test_cursor_property(self):
        self.assertEqual(self.storage.cursor, self.storage._cursor)

    def test_get_ports_by_node(self):
        node = Node(node_id=3, ip=ipaddress.ip_address('127.0.0.1'))
        result = self.storage.get_ports_by_node(node, 1200)
        expected = "SELECT id, ip, port, protocol, time FROM ports where id=? AND ip=? AND time > ?", (3, '127.0.0.1', 1200,)

        self.assertEqual(result, expected)

    def test_get_ports_by_nodes(self):
        nodes = [
            Node(node_id=3, ip=ipaddress.ip_address('127.0.0.1')),
            Node(node_id=7, ip=ipaddress.ip_address('::1'))
        ]

        result = self.storage.get_ports_by_nodes(nodes, 1200)
        expected = (
            "SELECT id, ip, port, protocol, time FROM ports where ( (id=? AND ip=?) OR (id=? AND ip=?) ) AND time > ?",
            [3, '127.0.0.1', 7, '::1', 1200]
        )

        self.assertEqual(result, expected)

    def test_clear_scan_details(self):
        result = self.storage.clear_scan_details()
        expected = "DELETE FROM scans WHERE scan_start >= scan_end OR scan_start IS NULL OR SCAN_END IS NULL",

        self.assertEqual(result, expected)

    def test_init_schema(self):
        self.storage.execute = MagicMock()
        self.storage.clear_scan_details = MagicMock()
        self.storage.create_tables = MagicMock()

        self.storage.init_schema()
        self.storage.execute.assert_has_calls((call(self.storage.create_tables.return_value),
                                               call(self.storage.clear_scan_details.return_value)), any_order=False)
        self.storage.clear_scan_details.assert_called_once_with()
        self.storage.create_tables.assert_called_once_with()
