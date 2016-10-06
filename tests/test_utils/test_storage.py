import ipaddress
from unittest import TestCase

from sqlite3 import Connection, DatabaseError

from sqlite3 import connect
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, Scan
from utils.storage import Storage


class StorageTest(TestCase):

    def setUp(self):
        self.storage = Storage(":memory:")
        self.storage.lock = MagicMock()

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

    def test_save_node(self):
        node = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        with self.storage as storage:
            storage.save_node(node)

            result = storage.cursor.execute("SELECT * FROM nodes").fetchone()

        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], '127.0.0.1')

    def test_save_nodes(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        with self.storage as storage:
            storage.save_nodes(nodes)

            result = storage.cursor.execute("SELECT * FROM nodes").fetchall()

        self.assertEqual(result[0][0], 1)
        self.assertEqual(result[0][1], '127.0.0.1')

        self.assertEqual(result[1][0], 2)
        self.assertEqual(result[1][1], '127.0.0.2')

        self.assertEqual(result[2][0], 3)
        self.assertEqual(result[2][1], '127.0.0.3')

    def test_get_nodes(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        with self.storage as storage:
            storage.save_nodes(nodes)

            result = storage.get_nodes(1000)

            for i in range(len(result)):
                self.assertEqual(result[i].ip, nodes[i].ip)
                self.assertEqual(result[i].name, nodes[i].name)
                self.assertEqual(result[i].id, nodes[i].id)

    def test_get_nodes_exception(self):
        self.storage._cursor = MagicMock()
        self.storage._cursor.execute = MagicMock(side_effect=DatabaseError)

        result = self.storage.get_nodes(1000)
        self.assertEqual(result, [])

    @patch('utils.storage.threading.Lock', MagicMock())
    def test_save_port(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1), transport_protocol=TransportProtocol.TCP,
                    number=1)
        with Storage(":memory:") as storage:
            storage.save_port(port)

            expected = storage.cursor.execute("SELECT * FROM ports").fetchone()

        self.assertEqual(expected[0], 1)
        self.assertEqual(expected[1], '127.0.0.1')
        self.assertEqual(expected[2], 1)
        self.assertEqual(expected[3], TransportProtocol.TCP.iana)

    def test_save_ports(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        ports = [Port(node=nodes[0], transport_protocol=TransportProtocol.TCP, number=5),
                 Port(node=nodes[1], transport_protocol=TransportProtocol.UDP, number=65),
                 Port(node=nodes[2], transport_protocol=TransportProtocol.ICMP, number=99),]

        with self.storage as storage:
            storage.save_ports(ports)

            expected = storage.cursor.execute("SELECT * FROM ports").fetchall()

        for i in range(len(expected)):
            self.assertEqual(expected[i][0], ports[i].node.id)
            self.assertEqual(expected[i][1], str(ports[i].node.ip))
            self.assertEqual(expected[i][2], ports[i].number)
            self.assertEqual(expected[i][3], ports[i].transport_protocol.iana)

    def test_get_ports(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        ports = [Port(node=nodes[0], transport_protocol=TransportProtocol.TCP, number=5),
                 Port(node=nodes[1], transport_protocol=TransportProtocol.UDP, number=65),
                 Port(node=nodes[2], transport_protocol=TransportProtocol.ICMP, number=99),]

        with self.storage as storage:
            storage.save_ports(ports)

            expected = storage.get_ports(1000)

            for i in range(3):
                self.assertEqual(expected[i].node.ip, ports[i].node.ip)
                self.assertEqual(expected[i].node.id, ports[i].node.id)

    def test_get_ports_exception(self):
        self.storage._cursor = MagicMock()
        self.storage._cursor.execute = MagicMock(side_effect=DatabaseError)

        result = self.storage.get_ports(1000)
        self.assertEqual(result, [])

    @patch('utils.storage.threading.Lock', MagicMock())
    def test_save_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan)

        with Storage(":memory:") as storage:
            storage.save_scan(exploit=exploit, port=port)

            result = storage.cursor.execute("SELECT * FROM scans").fetchall()

        self.assertEqual(result[0][0], exploit.id)
        self.assertEqual(result[0][1], exploit.app)
        self.assertEqual(result[0][2], exploit.name)
        self.assertEqual(result[0][3], port.node.id)
        self.assertEqual(result[0][4], str(port.node.ip))
        self.assertEqual(result[0][5], port.transport_protocol.iana)
        self.assertEqual(result[0][6], port.number)
        self.assertEqual(result[0][7], start_scan)
        self.assertEqual(result[0][8], None)

    @patch('utils.storage.threading.Lock', MagicMock())
    def test_save_scan_without_changing_start_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan, end=start_scan)

        with Storage(":memory:") as storage:
            storage.save_scan(exploit=exploit, port=port)

            result = storage.cursor.execute("SELECT * FROM scans").fetchall()

        self.assertEqual(result[0][7], start_scan)

    @patch('utils.storage.threading.Lock', MagicMock())
    def test_get_scan_info(self):
        exploits = [Exploit(exploit_id=14, name='test_name_1', app='test_app'),
                    Exploit(exploit_id=20, name='test_name_2', app='test_app'),
                    Exploit(exploit_id=25, name='test_name_3', app='test_app'),
                    Exploit(exploit_id=30, name='test_name_4', app='test_app2'),
                    Exploit(exploit_id=35, name='test_name_5', app='test_app2')]

        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3)

        ports = [Port(node=node, number=12, transport_protocol=TransportProtocol.TCP),
                 Port(node=node, number=15, transport_protocol=TransportProtocol.TCP)]

        start_scan = 17.0
        end_scan = 27.0

        with Storage(":memory:") as storage:
            for exploit in exploits:
                for port in ports:
                    port.scan = Scan(start=start_scan, end=end_scan)
                    storage.save_scan(exploit=exploit, port=port)

            results = storage.get_scan_info(port=ports[0], app='test_app')

        expected = [
            {
                "exploit": exploits[0],
                "port": ports[0],
                "scan_start": start_scan,
                "scan_end": end_scan,
                "exploit_name": "test_name_1"
            },
            {
                "exploit": exploits[1],
                "port": ports[0],
                "scan_start": start_scan,
                "scan_end": end_scan,
                "exploit_name": "test_name_2"
            },
            {
                "exploit": exploits[2],
                "port": ports[0],
                "scan_start": start_scan,
                "scan_end": end_scan,
                "exploit_name": "test_name_3"
            }
        ]

        self.assertCountEqual(results, expected)

    def test_get_scan_info_exception(self):
        self.storage._cursor = MagicMock()
        self.storage._cursor.execute = MagicMock(side_effect=DatabaseError)

        result = self.storage.get_scan_info(port=Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1),
                                                      number=1, transport_protocol=TransportProtocol.TCP), app=None)
        self.assertEqual(result, [])

    @patch('utils.storage.threading.Lock', MagicMock())
    def test_clear_scan_details(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)
        port.scan = Scan()

        start_scan = 17

        with Storage(":memory:") as storage:
            port.scan.start = start_scan
            storage.save_scan(exploit=exploit, port=port)

            port.number += 1
            port.scan.end = start_scan -1
            storage.save_scan(exploit=exploit, port=port)

            port.number += 1
            port.scan.end +=1
            storage.save_scan(exploit=exploit, port=port)

            port.number += 1
            port.scan.end += 1
            storage.save_scan(exploit=exploit, port=port)

            port.number += 1
            port.scan.start = None
            storage.save_scan(exploit=exploit, port=port)
            storage.clear_scan_details()

            result = len(storage.cursor.execute("SELECT * FROM scans").fetchall())

        expected = 1

        self.assertEqual(result, expected)

    def test_create_table(self):
        with Storage(":memory:") as storage:
            storage.create_tables()
            nodes_result = storage.cursor.execute("PRAGMA table_info(nodes);").fetchall()
            scans_result = storage.cursor.execute("PRAGMA table_info(scans);").fetchall()
            ports_result = storage.cursor.execute("PRAGMA table_info(ports);").fetchall()

        nodes_expected = [
            (0, 'id', 'int', 0, None, 1),
            (1, 'ip', 'text', 0, None, 2),
            (2, 'time', 'int', 0, None, 0),
        ]

        scans_expected = [
            (0, 'exploit_id', 'int', 0, None, 1),
            (1, 'exploit_app', 'text', 0, None, 0),
            (2, 'exploit_name', 'text', 0, None, 0),
            (3, 'node_id', 'int', 0, None, 2),
            (4, 'node_ip', 'text', 0, None, 3),
            (5, 'port_protocol', 'int', 0, None, 4),
            (6, 'port_number', 'int', 0, None, 5),
            (7, 'scan_start', 'float', 0, None, 0),
            (8, 'scan_end', 'float', 0, None, 0),
        ]

        ports_expected = [
            (0, 'id', 'int', 0, None, 1),
            (1, 'ip', 'text', 0, None, 2),
            (2, 'port', 'int', 0, None, 3),
            (3, 'protocol', 'int', 0, None, 4),
            (4, 'time', 'int', 0, None, 0),
        ]

        self.assertCountEqual(nodes_result, nodes_expected)
        self.assertCountEqual(scans_result, scans_expected)
        self.assertCountEqual(ports_result, ports_expected)

    def test_clear_scan_details_with_db_error(self):
        with Storage(":memory:") as storage:
            storage._cursor = MagicMock()
            storage._cursor.execute = MagicMock(side_effect=DatabaseError)

            self.assertRaises(DatabaseError, storage.clear_scan_details)