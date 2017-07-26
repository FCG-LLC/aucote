import ipaddress
from unittest import TestCase

from sqlite3 import Connection

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
    def test__save_node(self):
        node = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        result = self.storage._save_node(node, protocol=TransportProtocol.TCP)
        expected = ("INSERT OR REPLACE INTO nodes (id, ip, time, protocol) VALUES (?, ?, ?, ?)", (1, '127.0.0.1', 7, 6))

        self.assertCountEqual(result, expected)

    @patch("time.time", MagicMock(return_value=17))
    def test__save_nodes(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        result = self.storage._save_nodes(nodes, protocol=TransportProtocol.TCP)
        expected = (
            ("INSERT OR REPLACE INTO nodes (id, ip, time, protocol) VALUES (?, ?, ?, ?)", (1, '127.0.0.1', 17, 6)),
            ("INSERT OR REPLACE INTO nodes (id, ip, time, protocol) VALUES (?, ?, ?, ?)", (2, '127.0.0.2', 17, 6)),
            ("INSERT OR REPLACE INTO nodes (id, ip, time, protocol) VALUES (?, ?, ?, ?)", (3, '127.0.0.3', 17, 6)),
        )

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))
    def test__get_nodes(self):
        result = self.storage._get_nodes(pasttime=700, timestamp=None, protocol=TransportProtocol.UDP)
        expected = 'SELECT id, ip, time FROM nodes where time > ? AND (protocol=? OR (? IS NULL AND protocol IS NULL))', (139300, 17, 17)
        self.assertEqual(result, expected)

    @patch('time.time', MagicMock(return_value=13))
    def test__save_port(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1),
                    transport_protocol=TransportProtocol.TCP, number=1)

        result = self.storage._save_port(port)

        expected = ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                    (1, '127.0.0.1', 1, 6, 13))

        self.assertCountEqual(result, expected)

    @patch('time.time', MagicMock(return_value=122))
    def test__save_ports(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        ports = [Port(node=nodes[0], transport_protocol=TransportProtocol.TCP, number=5),
                 Port(node=nodes[1], transport_protocol=TransportProtocol.UDP, number=65),
                 Port(node=nodes[2], transport_protocol=TransportProtocol.ICMP, number=99), ]

        result = self.storage._save_ports(ports)

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
    def test__get_ports(self):
        result = self.storage._get_ports(700)
        expected = 'SELECT id, ip, port, protocol, time FROM ports where time > ?', (139300,)
        self.assertEqual(result, expected)

    def test__save_scan(self):
        exploit = Exploit(exploit_id=14, name='test_name', app='test_app')

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan)
        result = self.storage._save_scan(exploit=exploit, port=port)

        expected = [
            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 12)),
            ("UPDATE scans SET scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
              (17, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 6, 12))
        ]

        self.assertCountEqual(result[0], expected[0])
        self.assertCountEqual(result[1], expected[1])

    def test__save_scans(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        exploit_2 = Exploit(exploit_id=2)
        exploit_2.name = 'test_name_2'
        exploit_2.app = 'test_app_2'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        port.scan = Scan(start=3, end=45)
        result = self.storage._save_scans(exploits=[exploit, exploit_2], port=port)

        expected = [
            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
             "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
             (14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 12)),

            ("UPDATE scans SET scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
             (3, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 6, 12)),

            ("UPDATE scans SET scan_end=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
             (45, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 6, 12)),

            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
             "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
             (2, 'test_app_2', 'test_name_2', 3, '127.0.0.1', 6, 12)),

            ("UPDATE scans SET scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
             (3, 2, 'test_app_2', 'test_name_2', 3, '127.0.0.1', 6, 6, 12)),

            ("UPDATE scans SET scan_end=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
             (45, 2, 'test_app_2', 'test_name_2', 3, '127.0.0.1', 6, 6, 12))
        ]

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    def test__save_scan_without_changing_start_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan, end=start_scan)
        result = self.storage._save_scan(exploit=exploit, port=port)

        expected = [
            ("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 12)),
            ("UPDATE scans SET scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
              (17, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 6, 12)),
            ("UPDATE scans SET scan_end=? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?",
              (17, 14, 'test_app', 'test_name', 3, '127.0.0.1', 6, 6, 12))
        ]

        self.assertCountEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))
    def test__get_scan_info(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        result = self.storage._get_scan_info(port=port, app='test_app')
        expected = ('SELECT exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, port_number, '
                    'scan_start, scan_end FROM scans WHERE exploit_app=? AND node_id=? AND node_ip=? '
                    'AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=?', ('test_app', 3, '127.0.0.1', 6, 6, 12))

        self.assertCountEqual(result, expected)

    def test__create_table(self):
        result = self.storage._create_tables()
        expected = [
            ("CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, exploit_name text, "
              "node_id int, node_ip text, port_protocol int, port_number int, scan_start float, "
              "scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, port_number))",),

            ("CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, time int,"
              "primary key (id, ip, port, protocol))",),

            ("CREATE TABLE IF NOT EXISTS nodes(id int, ip text, time int, protocol int, primary key (id, ip, protocol))",),
        ]

        self.assertCountEqual(result, expected)

    def test_cursor_property(self):
        self.assertEqual(self.storage.cursor, self.storage._cursor)

    def test__get_ports_by_node(self):
        node = Node(node_id=3, ip=ipaddress.ip_address('127.0.0.1'))
        result = self.storage._get_ports_by_node(node, 1200, protocol=TransportProtocol.TCP)
        expected = "SELECT id, ip, port, protocol, time FROM ports where id=? AND ip=? AND time > ? AND (protocol=? OR (? IS NULL AND protocol IS NULL))", (3, '127.0.0.1', 1200, 6, 6)

        self.assertEqual(result, expected)

    def test__get_ports_by_node_all_protocols(self):
        node = Node(node_id=3, ip=ipaddress.ip_address('127.0.0.1'))
        result = self.storage._get_ports_by_node(node, 1200, protocol=None)
        expected = "SELECT id, ip, port, protocol, time FROM ports where id=? AND ip=? AND time > ?", (3, '127.0.0.1', 1200)

        self.assertEqual(result, expected)

    def test__get_ports_by_nodes(self):
        nodes = [
            Node(node_id=3, ip=ipaddress.ip_address('127.0.0.1')),
            Node(node_id=7, ip=ipaddress.ip_address('::1'))
        ]

        result = self.storage._get_ports_by_nodes(nodes, 1200, protocol=TransportProtocol.UDP)
        expected = (
            "SELECT id, ip, port, protocol, time FROM ports where ( (id=? AND ip=?) OR (id=? AND ip=?) ) AND time > ? AND (protocol=? OR (? IS NULL AND protocol IS NULL))",
            [3, '127.0.0.1', 7, '::1', 1200, 17, 17]
        )

        self.assertEqual(result, expected)

    def test__get_ports_by_nodes_all_protocols(self):
        nodes = [
            Node(node_id=3, ip=ipaddress.ip_address('127.0.0.1')),
            Node(node_id=7, ip=ipaddress.ip_address('::1'))
        ]

        result = self.storage._get_ports_by_nodes(nodes, 1200, protocol=None)
        expected = (
            "SELECT id, ip, port, protocol, time FROM ports where ( (id=? AND ip=?) OR (id=? AND ip=?) ) AND time > ?",
            [3, '127.0.0.1', 7, '::1', 1200]
        )

        self.assertEqual(result, expected)

    def test__clear_scan_details(self):
        result = self.storage._clear_scan_details()
        expected = "DELETE FROM scans WHERE scan_start >= scan_end OR scan_start IS NULL OR SCAN_END IS NULL",

        self.assertEqual(result, expected)

    def test_init_schema(self):
        self.storage.execute = MagicMock()
        self.storage._clear_scan_details = MagicMock()
        self.storage._create_tables = MagicMock()

        self.storage.init_schema()
        self.storage.execute.assert_has_calls((call(self.storage._create_tables.return_value),
                                               call(self.storage._clear_scan_details.return_value)), any_order=False)
        self.storage._clear_scan_details.assert_called_once_with()
        self.storage._create_tables.assert_called_once_with()

    def test_save_node(self):
        node = MagicMock()
        self.storage._save_node = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_node(node=node, protocol=TransportProtocol.UDP)
        self.storage._save_node.assert_called_once_with(node=node, protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._save_node())

    def test_save_nodes(self):
        nodes = MagicMock()
        self.storage._save_nodes = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_nodes(nodes=nodes, protocol=TransportProtocol.UDP)
        self.storage._save_nodes.assert_called_once_with(nodes=nodes, protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._save_nodes())

    def test_get_nodes(self):
        self.storage._get_nodes = MagicMock()
        timestamp = MagicMock()
        pasttime = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1'),
            (2, '::1'),
        ))

        result = self.storage.get_nodes(pasttime=pasttime, timestamp=timestamp, protocol=TransportProtocol.UDP)

        self.storage._get_nodes.assert_called_once_with(pasttime=pasttime, timestamp=timestamp,
                                                        protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._get_nodes())

        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 2)

        self.assertEqual(result[0].ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].ip, ipaddress.ip_address('::1'))

    def test_save_port(self):
        port = MagicMock()
        self.storage._save_port = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_port(port=port)
        self.storage._save_port.assert_called_once_with(port=port)
        self.storage.execute.assert_called_once_with(self.storage._save_port())

    def test_save_ports(self):
        ports = MagicMock()
        self.storage._save_ports = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_ports(ports=ports)
        self.storage._save_ports.assert_called_once_with(ports=ports)
        self.storage.execute.assert_called_once_with(self.storage._save_ports())

    def test_get_ports(self):
        self.storage._get_ports = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1', 20, 6),
            (2, '::1', 23, 17),
        ))

        result = self.storage.get_ports(pasttime=100)

        self.storage._get_ports.assert_called_once_with(pasttime=100)
        self.storage.execute.assert_called_once_with(self.storage._get_ports(pasttime=100))

        self.assertEqual(result[0].node.id, 1)
        self.assertEqual(result[1].node.id, 2)

        self.assertEqual(result[0].node.ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].node.ip, ipaddress.ip_address('::1'))

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)

        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)

    def test_save_scan(self):
        exploit = MagicMock()
        port = MagicMock()
        self.storage._save_scan = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_scan(exploit=exploit, port=port)
        self.storage._save_scan.assert_called_once_with(exploit=exploit, port=port)
        self.storage.execute.assert_called_once_with(self.storage._save_scan())

    def test_save_scans(self):
        exploits = MagicMock()
        port = MagicMock()
        self.storage._save_scans = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_scans(exploits=exploits, port=port)
        self.storage._save_scans.assert_called_once_with(exploits=exploits, port=port)
        self.storage.execute.assert_called_once_with(self.storage._save_scans())

    def test_get_scan_info(self):
        port = MagicMock()
        app = MagicMock()

        self.storage.execute = MagicMock(return_value=(
            (11, None, 'test_name', 1, '127.0.0.1', 6, 11, 10., 10.),
            (22, None, 'test_name_2', 2, '::1', 17, 22, None, None),
        ))
        self.storage._get_scan_info = MagicMock()

        result = self.storage.get_scan_info(port, app)
        self.storage._get_scan_info.assert_called_once_with(port=port, app=app)
        self.storage.execute.assert_called_once_with(self.storage._get_scan_info())

        self.assertEqual(result[0]['port'].node.id, 1)
        self.assertEqual(result[1]['port'].node.id, 2)

        self.assertEqual(result[0]['port'].node.ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1]['port'].node.ip, ipaddress.ip_address('::1'))

        self.assertEqual(result[0]['port'].number, 11)
        self.assertEqual(result[1]['port'].number, 22)

        self.assertEqual(result[0]['port'].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1]['port'].transport_protocol, TransportProtocol.UDP)

        self.assertEqual(result[0]['exploit_name'], 'test_name')
        self.assertEqual(result[1]['exploit_name'], 'test_name_2')

        self.assertEqual(result[0]['scan_start'], 10.)
        self.assertEqual(result[1]['scan_start'], 0.)

        self.assertEqual(result[0]['scan_end'], 10.)
        self.assertEqual(result[1]['scan_end'], 0.)

        self.assertEqual(result[0]['exploit'].id, 11)
        self.assertEqual(result[1]['exploit'].id, 22)

    def test_clear_scan_details(self):
        self.storage._clear_scan_details = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.clear_scan_details()
        self.storage._clear_scan_details.assert_called_once_with()
        self.storage.execute.assert_called_once_with(self.storage._clear_scan_details())

    def test_create_tables(self):
        self.storage._create_tables = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.create_tables()
        self.storage._create_tables.assert_called_once_with()
        self.storage.execute.assert_called_once_with(self.storage._create_tables())

    def test_get_ports_by_node(self):
        node = MagicMock()
        self.storage._get_ports_by_node = MagicMock()
        timestamp = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1', 20, 6),
            (1, '127.0.0.1', 23, 17),
        ))

        result = self.storage.get_ports_by_node(node=node, timestamp=timestamp, protocol=TransportProtocol.UDP)

        self.storage._get_ports_by_node.assert_called_once_with(node=node, timestamp=timestamp,
                                                                protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._get_ports_by_node())

        self.assertEqual(result[0].node, node)
        self.assertEqual(result[1].node, node)

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)


    @patch('utils.storage.time.time', MagicMock(return_value=37))
    def test_get_ports_by_node_without_timestamp(self):
        node = MagicMock()
        pasttime = 30
        self.storage._get_ports_by_node = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.get_ports_by_node(node=node, pasttime=pasttime, protocol=TransportProtocol.UDP)
        self.storage._get_ports_by_node.assert_called_once_with(node=node, timestamp=7, protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._get_ports_by_node())

    def test_get_ports_by_nodes_without_nodes(self):
        nodes = []
        expected = []

        result = self.storage.get_ports_by_nodes(nodes)

        self.assertEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=108))
    def test_get_ports_by_nodes(self):
        pasttime = 30
        self.storage._get_ports_by_nodes = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1', 20, 6),
            (2, '::1', 23, 17),
            (1, '127.0.0.1', 14, 17),
        ))

        node_1 = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        node_1.name = 'test'
        node_1.scan = Scan(start=15)
        node_2 = Node(node_id=2, ip=ipaddress.ip_address('::1'))
        node_2.scan = Scan(start=15)
        node_2.name = 'test'

        nodes = [node_1, node_2]
        result = self.storage.get_ports_by_nodes(nodes, pasttime=pasttime, protocol=TransportProtocol.UDP)
        self.storage._get_ports_by_nodes.assert_called_once_with(nodes=nodes, timestamp=78,
                                                                 protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._get_ports_by_nodes())

        self.assertEqual(result[0].node, node_1)
        self.assertEqual(result[0].node.name, node_1.name)
        self.assertEqual(result[1].node, node_2)
        self.assertEqual(result[1].node.name, node_2.name)
        self.assertEqual(result[2].node, node_1)

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)
        self.assertEqual(result[2].number, 14)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)
        self.assertEqual(result[2].transport_protocol, TransportProtocol.UDP)

        self.assertEqual(result[0].scan.start, node_1.scan.start)
        self.assertEqual(result[1].scan.start, node_2.scan.start)
        self.assertEqual(result[2].scan.start, node_1.scan.start)

    def test_execute_query(self):
        query = "part_1", "arg_1", "arg_2"
        self.storage._cursor = MagicMock()

        result = self.storage.execute(query)
        self.storage.cursor.execute.assert_called_once_with("part_1", "arg_1", "arg_2")
        self.storage.cursor.execute().fetchall.assert_called_once_with()
        self.assertEqual(result, self.storage.cursor.execute().fetchall())

    def test_execute_query_list(self):
        queries = [("part_1", "arg_1", "arg_2"), ("part_2", "arg_3")]
        self.storage._cursor = MagicMock()
        self.storage.conn = MagicMock()

        self.storage.execute(queries)
        self.storage.cursor.execute.assert_has_calls((call("part_1", "arg_1", "arg_2"), call("part_2", "arg_3")))
        self.storage.conn.commit.assert_called_once_with()

    def test_transport_protocol_none(self):
        result = self.storage._transport_protocol(None)
        self.assertIsNone(result)

    @patch('utils.storage.TransportProtocol')
    def test_transport_protocol(self, protocol):
        result = self.storage._transport_protocol(6)
        protocol.from_iana.assert_called_once_with(6)
        self.assertEqual(result, protocol.from_iana())

    def test_protocol_to_iana_none(self):
        protocol = None
        result = self.storage._protocol_to_iana(protocol)
        self.assertIsNone(result)
