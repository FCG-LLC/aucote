import ipaddress
from types import GeneratorType
from unittest import TestCase

from sqlite3 import Connection, DatabaseError, time

from sqlite3 import connect
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, Scan
from utils.storage import Storage


class StorageTest(TestCase):
    def setUp(self):
        self.task = MagicMock()
        self.storage = Storage(self.task, filename=":memory:")

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
        self.storage.save_node(node)

        result = self.task.add_query.call_args[0]
        expected = (("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (1, '127.0.0.1', 7)),)

        self.assertCountEqual(result, expected)

    @patch("time.time", MagicMock(return_value=17))
    def test_save_nodes(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        self.storage.save_nodes(nodes)

        result = self.task.add_query.call_args[0]
        expected = (
            ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (1, '127.0.0.1', 17)),
            ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (2, '127.0.0.2', 17)),
            ("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (3, '127.0.0.3', 17)),
        )

        self.assertCountEqual(result[0], expected)
        self.assertIsInstance(result[0], list)

    def test_get_nodes(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        with self.storage as storage:
            storage.cursor.execute("CREATE TABLE nodes (id int, ip text, time float)")
            storage.cursor.execute("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (1, '127.0.0.1',
                                                                                                    time.time()))
            storage.cursor.execute("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (2, '127.0.0.2',
                                                                                                    time.time()))
            storage.cursor.execute("INSERT OR REPLACE INTO nodes (id, ip, time) VALUES (?, ?, ?)", (3, '127.0.0.3',
                                                                                                    time.time()))

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

    @patch('time.time', MagicMock(return_value=13))
    def test_save_port(self):
        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1),
                    transport_protocol=TransportProtocol.TCP, number=1)

        self.storage.save_port(port)

        result = self.task.add_query.call_args[0]
        expected = (("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                     (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana, 13)),)

        self.assertCountEqual(result, expected)

    @patch('time.time', MagicMock(return_value=122))
    def test_save_ports(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        ports = [Port(node=nodes[0], transport_protocol=TransportProtocol.TCP, number=5),
                 Port(node=nodes[1], transport_protocol=TransportProtocol.UDP, number=65),
                 Port(node=nodes[2], transport_protocol=TransportProtocol.ICMP, number=99), ]

        self.storage.save_ports(ports)

        result = self.task.add_query.call_args[0]
        expected = [
            ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
             (1, '127.0.0.1', 5, 6, 122)),
            ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
             (2, '127.0.0.2', 65, 17, 122)),
            ("INSERT OR REPLACE INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
             (3, '127.0.0.3', 99, 1, 122)),
        ]

        self.assertCountEqual(result[0], expected)
        self.assertIsInstance(result[0], list)

    def test_get_ports(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')),
                 Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2')),
                 Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))]

        ports = [Port(node=nodes[0], transport_protocol=TransportProtocol.TCP, number=5),
                 Port(node=nodes[1], transport_protocol=TransportProtocol.UDP, number=65),
                 Port(node=nodes[2], transport_protocol=TransportProtocol.ICMP, number=99), ]

        with self.storage as storage:
            storage.cursor.execute("CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, "
                                   "time int, primary key (id, ip, port, protocol))")

            for port in ports:
                storage.cursor.execute("INSERT INTO ports (id, ip, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                                       (port.node.id, str(port.node.ip), port.number, port.transport_protocol.iana,
                                        time.time()))

            expected = storage.get_ports(1000)

            for i in range(3):
                self.assertEqual(expected[i].node.ip, ports[i].node.ip)
                self.assertEqual(expected[i].node.id, ports[i].node.id)

    def test_get_ports_exception(self):
        self.storage._cursor = MagicMock()
        self.storage._cursor.execute = MagicMock(side_effect=DatabaseError)

        result = self.storage.get_ports(1000)
        self.assertEqual(result, [])

    def test_save_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan)
        self.storage.save_scan(exploit=exploit, port=port)

        result = self.task.add_query.call_args_list

        expected = [
            (("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
               port.transport_protocol.iana, port.number)),),
            (("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
              (port.scan.start, exploit.id, exploit.app, exploit.name, port.node.id,
               str(port.node.ip), port.transport_protocol.iana, port.number)),)
        ]

        self.assertCountEqual(result[0][0], expected[0])
        self.assertCountEqual(result[1][0], expected[1])

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

        self.storage.save_scans(exploits=[exploit, exploit_2], port=port)

        result = self.task.add_query.call_args[0]

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

        self.assertCountEqual(result[0], expected)
        self.assertIsInstance(result[0], list)

    def test_save_scan_without_changing_start_scan(self):
        exploit = Exploit(exploit_id=14)
        exploit.name = 'test_name'
        exploit.app = 'test_app'

        port = Port(node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=3), number=12,
                    transport_protocol=TransportProtocol.TCP)

        start_scan = 17
        port.scan = Scan(start=start_scan, end=start_scan)
        self.storage.save_scan(exploit=exploit, port=port)

        result = self.task.add_query.call_args_list

        expected = [
            (("INSERT OR IGNORE INTO scans (exploit_id, exploit_app, exploit_name, node_id, node_ip,"
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
               port.transport_protocol.iana, port.number)),),
            (("UPDATE scans SET scan_start = ? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
              (port.scan.start, exploit.id, exploit.app, exploit.name, port.node.id,
               str(port.node.ip), port.transport_protocol.iana, port.number)),),
            (("UPDATE scans SET scan_end = ? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND port_protocol=? AND port_number=?",
              (port.scan.end, exploit.id, exploit.app, exploit.name, port.node.id,
               str(port.node.ip), port.transport_protocol.iana, port.number)),)
        ]

        self.assertCountEqual(result[0][0], expected[0])
        self.assertCountEqual(result[1][0], expected[1])
        self.assertCountEqual(result[2][0], expected[2])

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

        with Storage(MagicMock(), filename=":memory:") as storage:
            storage.cursor.execute("CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, "
                                   "exploit_name text, node_id int, node_ip text, port_protocol int, port_number int, "
                                   "scan_start float, scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, "
                                   "port_protocol, port_number))")

            for exploit in exploits:
                for port in ports:
                    port.scan = Scan(start=start_scan, end=end_scan)
                    storage.cursor.execute("INSERT INTO scans (exploit_id, exploit_app, exploit_name, node_id,"
                                           "node_ip, port_protocol, port_number, scan_start, scan_end) "
                                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                           (exploit.id, exploit.app, exploit.name, port.node.id, str(port.node.ip),
                                            port.transport_protocol.iana, port.number, start_scan, end_scan))
            storage.conn.commit()

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

    def test_create_table(self):
        self.storage.create_tables()
        result = self.task.add_query.call_args_list
        expected = [
            (("CREATE TABLE IF NOT EXISTS scans (exploit_id int, exploit_app text, exploit_name text, "
              "node_id int, node_ip text, port_protocol int, port_number int, scan_start float, "
              "scan_end float, PRIMARY KEY (exploit_id, node_id, node_ip, port_protocol, port_number))",),),

            (("CREATE TABLE IF NOT EXISTS ports (id int, ip text, port int, protocol int, time int,"
              "primary key (id, ip, port, protocol))",),),

            (("CREATE TABLE IF NOT EXISTS nodes(id int, ip text, time int, primary key (id, ip))",),)
        ]

        self.assertCountEqual(result[0][0], expected[0])
        self.assertCountEqual(result[1][0], expected[1])
        self.assertCountEqual(result[2][0], expected[2])
