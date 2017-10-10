import ipaddress
from unittest import TestCase

from sqlite3 import Connection

from sqlite3 import connect
from unittest.mock import MagicMock, patch, call

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, Scan, Vulnerability, VulnerabilityChangeBase, \
    VulnerabilityChangeType, PortDetectionChange
from utils.storage import Storage


class StorageTest(TestCase):
    def setUp(self):
        self.maxDiff = None
        self.storage = Storage(filename=":memory:")
        self.scan = Scan(start=1, end=17, protocol=TransportProtocol.UDP, scanner='test_name')

        self.node_1 = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        self.node_1.name = 'test_node_1'
        self.node_1.scan = Scan(start=15)

        self.node_2 = Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2'))
        self.node_2.name = 'test_node_2'
        self.node_2.scan = Scan(start=56)

        self.node_3 = Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))
        self.node_3.name = 'test_node_3'
        self.node_3.scan = Scan(start=98)

        self.port_1 = Port(node=self.node_1, number=45, transport_protocol=TransportProtocol.UDP)
        self.port_1.scan = Scan(start=17)
        self.port_1.row_id = 124

        self.port_2 = Port(node=self.node_2, transport_protocol=TransportProtocol.TCP, number=65)
        self.port_2.scan = Scan(start=3, end=45)
        self.port_2.row_id = 15

        self.port_3 = Port(node=self.node_3, transport_protocol=TransportProtocol.ICMP, number=99)
        self.port_3.scan = Scan(start=43, end=180)
        self.port_3.row_id = 13

        self.exploit_1 = Exploit(exploit_id=14, name='test_name', app='test_app')
        self.exploit_2 = Exploit(exploit_id=2, name='test_name_2', app='test_app_2')

        self.vuln_change_1 = PortDetectionChange(change_time=124445, current_finding=self.port_1,
                                                 previous_finding=self.port_2)

        self.vuln_change_2 = PortDetectionChange(change_time=32434, current_finding=self.port_2,
                                                 previous_finding=self.port_3)

        self.vulnerability_1 = Vulnerability(port=self.port_1, output='test_output_1', exploit=self.exploit_1,
                                             cve='CVE-2017', cvss=6.7, subid=1, vuln_time=13)
        self.vulnerability_2 = Vulnerability(port=self.port_1, output='test_output_2', exploit=self.exploit_2,
                                             cve='CWE-14', cvss=8.9, subid=2, vuln_time=98)

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
        self.storage.get_scan_id = MagicMock(return_value=16)
        result = self.storage._save_node(self.node_1, scan=self.scan)
        expected = ("INSERT OR REPLACE INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)",
                    (16, 1, '127.0.0.1', 7))

        self.assertCountEqual(result, expected)

    @patch("time.time", MagicMock(return_value=17))
    def test__save_nodes(self):
        self.storage.get_scan_id = MagicMock(return_value=16)
        nodes = [self.node_1, self.node_2, self.node_3]
        result = self.storage._save_nodes(nodes, scan=self.scan)
        expected = (
            ("INSERT OR REPLACE INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)", (16, 1, '127.0.0.1', 17)),
            ("INSERT OR REPLACE INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)", (16, 2, '127.0.0.2', 17)),
            ("INSERT OR REPLACE INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)", (16, 3, '127.0.0.3', 17)),
        )

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))
    def test__get_nodes(self):
        result = self.storage._get_nodes(pasttime=700, timestamp=None, scan=self.scan)

        expected = 'SELECT node_id, node_ip, time FROM nodes_scans INNER JOIN scans ON scan_id = scans.ROWID WHERE time>? '\
                   'AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?', (139300, 17, 17, 'test_name')
        self.assertEqual(result, expected)

    def test__get_vulnerabilities(self):
        self.storage.get_scan_id = MagicMock(return_value=16)
        result = self.storage._get_vulnerabilities(port=self.port_1, scan=self.scan, exploit=self.exploit_1)
        expected = 'SELECT scan_id, node_id, node_ip, port_protocol, port, vulnerability_id, ' \
                   'vulnerability_subid, cve, cvss, output, time, ROWID FROM vulnerabilities ' \
                   'WHERE node_id=? AND node_ip=? AND port=? AND (port_protocol=? OR (? IS NULL ' \
                   'AND port_protocol IS NULL)) AND vulnerability_id=? AND scan_id=?',\
                   (1, '127.0.0.1', 45, 17, 17, 14, 16),

        self.assertEqual(result, expected)

    @patch('time.time', MagicMock(return_value=13))
    def test__save_port(self):
        self.storage.get_scan_id = MagicMock(return_value=16)

        result = self.storage._save_port(self.port_1, scan=self.scan)

        expected = ("INSERT OR REPLACE INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) VALUES (?, ?, ?, ?, ?, ?)",
                    (16, 1, '127.0.0.1', 45, 17, 13))

        self.assertCountEqual(result, expected)

    @patch('time.time', MagicMock(return_value=122))
    def test__save_ports(self):
        ports = [self.port_1, self.port_2, self.port_3]

        self.storage.get_scan_id = MagicMock(return_value=34)

        result = self.storage._save_ports(ports, self.scan)
        self.storage.get_scan_id.assert_called_once_with(self.scan)

        expected = [
            ("INSERT OR REPLACE INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) VALUES (?, ?, ?, ?, ?, ?)",
             (34, 1, '127.0.0.1', 45, 17, 122)),
            ("INSERT OR REPLACE INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) VALUES (?, ?, ?, ?, ?, ?)",
             (34, 2, '127.0.0.2', 65, 6, 122)),
            ("INSERT OR REPLACE INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) VALUES (?, ?, ?, ?, ?, ?)",
             (34, 3, '127.0.0.3', 99, 1, 122)),
        ]

        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))
    def test__get_ports(self):
        self.storage.get_scan_id = MagicMock(return_value=87)
        result = self.storage._get_ports(700, scan=self.scan)
        expected = 'SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans INNER JOIN scans '\
                   'ON scan_id = scans.ROWID where time > ? AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?',\
                   (139300, 17, 17, 'test_name')
        self.assertEqual(result, expected)

    def test__get_scan_nodes(self):
        self.storage.get_scan_id = MagicMock(return_value=87)
        expected = 'SELECT node_id, node_ip, time, scan_id FROM nodes_scans WHERE scan_id=?', (87, )

        result = self.storage._get_scan_nodes(self.scan)

        self.assertEqual(result, expected)

    def test__get_scans_by_node(self):
        expected = "SELECT scans.ROWID, protocol, scanner_name, scan_start, scan_end FROM scans " \
                   "LEFT JOIN nodes_scans ON scans.ROWID = nodes_scans.scan_id WHERE node_id=? AND node_ip=? " \
                   " AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?"\
                   "ORDER BY scan_end DESC, scan_start ASC LIMIT 13 OFFSET 45", (1, '127.0.0.1', 17, 17, 'test_name')

        result = self.storage._get_scans_by_node(node=self.node_1, scan=self.scan, limit=13, offset=45)

        self.assertEqual(result, expected)

    def test__get_ports_by_node_and_scan(self):
        self.storage.get_scan_id = MagicMock(return_value=87)
        expected = "SELECT node_id, node_ip, port, port_protocol, time, ROWID FROM ports_scans where "\
                   "node_id=? AND node_ip=? AND scan_id=?", (1, '127.0.0.1', 87)

        result = self.storage._get_ports_by_node_and_scan(node=self.node_1, scan=self.scan)

        self.assertEqual(result, expected)

    def test__get_scan_by_id(self):
        scan_id = 77
        expected = "SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE scan_id=?", (77,)

        result = self.storage._get_scan_by_id(scan_id)

        self.assertEqual(result, expected)

    def test__save_security_scan(self):
        self.storage.get_scan_id = MagicMock(return_value=7)
        expected = [
            ("INSERT OR IGNORE INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name, node_id, node_ip, "
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (7, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 65)),
            ("UPDATE security_scans SET sec_scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
              (3, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 6, 65, 7))
        ]

        result = self.storage._save_security_scan(exploit=self.exploit_1, port=self.port_2, scan=self.scan)

        self.storage.get_scan_id.assert_called_once_with(self.scan)
        self.assertCountEqual(result[0], expected[0])
        self.assertCountEqual(result[1], expected[1])

    def test__save_security_scans(self):
        self.storage.get_scan_id = MagicMock(return_value=7)
        exploits = [self.exploit_1, self.exploit_2]
        expected = [
            ("INSERT OR IGNORE INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name, node_id, node_ip, "
             "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
             (7, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 65)),

            ("UPDATE security_scans SET sec_scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
             (3, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 6, 65, 7)),

            ("UPDATE security_scans SET sec_scan_end=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
             (45, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 6, 65, 7)),

            ("INSERT OR IGNORE INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name, node_id, node_ip, "
             "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
             (7, 2, 'test_app_2', 'test_name_2', 2, '127.0.0.2', 6, 65)),

            ("UPDATE security_scans SET sec_scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
             (3, 2, 'test_app_2', 'test_name_2', 2, '127.0.0.2', 6, 6, 65, 7)),

            ("UPDATE security_scans SET sec_scan_end=? WHERE exploit_id=? AND exploit_app=? AND "
             "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
             (45, 2, 'test_app_2', 'test_name_2', 2, '127.0.0.2', 6, 6, 65, 7))
        ]

        result = self.storage._save_security_scans(exploits=exploits, port=self.port_2, scan=self.scan)

        self.storage.get_scan_id.has_calls((call(self.scan), call(self.scan)))
        self.assertCountEqual(result, expected)
        self.assertIsInstance(result, list)

    def test__save_security_scan_without_changing_start_scan(self):
        self.storage.get_scan_id = MagicMock(return_value=7)
        expected = [
            ("INSERT OR IGNORE INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name, node_id, node_ip, "
              "port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (7, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 65)),
            ("UPDATE security_scans SET sec_scan_start=? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
              (3, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 6, 65, 7)),
            ("UPDATE security_scans SET sec_scan_end=? WHERE exploit_id=? AND exploit_app=? AND "
              "exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? AND scan_id=?",
              (45, 14, 'test_app', 'test_name', 2, '127.0.0.2', 6, 6, 65, 7))
        ]

        result = self.storage._save_security_scan(exploit=self.exploit_1, port=self.port_2, scan=self.scan)

        self.storage.get_scan_id.assert_called_once_with(self.scan)
        self.assertCountEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=140000))
    def test__get_scan_info(self):
        expected = ('SELECT exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, port_number, '
                    'sec_scan_start, sec_scan_end FROM security_scans INNER JOIN scans ON scan_id=scans.ROWID '
                    'WHERE exploit_app=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? '\
                    'AND (scans.protocol=? OR (? IS NULL AND scans.protocol IS NULL)) AND scans.scanner_name=?', ('test_app', 2, '127.0.0.2', 6, 6, 65, 17, 17, 'test_name'))

        result = self.storage._get_security_scan_info(port=self.port_2, app='test_app', scan=self.scan)

        self.assertCountEqual(result, expected)

    def test__save_change(self):
        expected = ("INSERT OR REPLACE INTO changes(type, vulnerability_id, vulnerability_subid, previous_id, " \
                    "current_id, time) VALUES (?, ?, ?, ?, ?, ?)",
                    (VulnerabilityChangeType.PORTDETECTION.value, 0, 0, 15, 124, 124445))

        result = self.storage._save_change(self.vuln_change_1)

        self.assertCountEqual(result, expected)

    def test__save_changes(self):
        changes = [self.vuln_change_1, self.vuln_change_2]

        expected = [("INSERT OR REPLACE INTO changes(type, vulnerability_id, vulnerability_subid, previous_id, " \
                    "current_id, time) VALUES (?, ?, ?, ?, ?, ?)",
                     (VulnerabilityChangeType.PORTDETECTION.value, 0, 0, 15, 124, 124445)),
                    ("INSERT OR REPLACE INTO changes(type, vulnerability_id, vulnerability_subid, previous_id, " \
                     "current_id, time) VALUES (?, ?, ?, ?, ?, ?)",
                     (VulnerabilityChangeType.PORTDETECTION.value, 0, 0, 13, 15, 32434))
                    ]

        result = self.storage._save_changes(changes)

        self.assertCountEqual(result, expected)

    def test__create_table(self):
        result = self.storage._create_tables()
        expected = [
            ("CREATE TABLE IF NOT EXISTS security_scans (scan_id int, exploit_id int, exploit_app text, "
              "exploit_name text, node_id int, node_ip text, port_protocol int, port_number int, sec_scan_start float, "
              "sec_scan_end float, PRIMARY KEY (scan_id, exploit_id, node_id, node_ip, port_protocol, port_number))",),

            ("CREATE TABLE IF NOT EXISTS ports_scans (scan_id int, node_id int, node_ip text, port int, port_protocol int,"
              " time int, primary key (scan_id, node_id, node_ip, port, port_protocol))",),

            ('CREATE TABLE IF NOT EXISTS nodes_scans(scan_id int, node_id int, node_ip text, time int, primary key (scan_id, node_id, node_ip))',),

            (
            'CREATE TABLE IF NOT EXISTS scans(protocol int, scanner_name str, scan_start int, scan_end int, UNIQUE '\
            '(protocol, scanner_name, scan_start))',),

            (
            'CREATE TABLE IF NOT EXISTS vulnerabilities(scan_id int, node_id int, node_ip int, '\
            'port_protocol int, port int, vulnerability_id int, vulnerability_subid int, cve text, cvss text, '\
            'output text, time int, primary key(scan_id, node_id, node_ip, port_protocol, port, '\
            'vulnerability_subid))',),

            (
                'CREATE TABLE IF NOT EXISTS changes(type int, vulnerability_id int, vulnerability_subid int, ' \
                'previous_id int, current_id int, time int, PRIMARY KEY(type, vulnerability_id, ' \
                'vulnerability_subid, previous_id, current_id, time))',
            )
        ]

        self.assertCountEqual(result, expected)

    def test_cursor_property(self):
        self.assertEqual(self.storage.cursor, self.storage._cursor)

    def test__get_ports_by_node(self):
        result = self.storage._get_ports_by_node(self.node_1, 1200, protocol=TransportProtocol.TCP)
        expected = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans where node_id=? AND node_ip=? AND "\
                   "time > ? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL))", (1, '127.0.0.1', 1200, 6, 6)

        self.assertEqual(result, expected)

    def test__get_ports_by_node_all_protocols(self):
        result = self.storage._get_ports_by_node(self.node_1, 1200, protocol=None)
        expected = "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans where node_id=? AND node_ip=? AND time > ?", (1, '127.0.0.1', 1200)

        self.assertEqual(result, expected)

    def test__get_ports_by_nodes(self):
        nodes = [ self.node_1, self.node_2]

        result = self.storage._get_ports_by_nodes(nodes, 1200, protocol=TransportProtocol.UDP)
        expected = (
            "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans where ( (node_id=? AND node_ip=?) OR "\
            "(node_id=? AND node_ip=?) ) AND time > ? AND (port_protocol=? OR (? IS NULL AND port_protocol IS NULL))",
            [1, '127.0.0.1', 2, '127.0.0.2', 1200, 17, 17]
        )

        self.assertEqual(result, expected)

    def test__get_ports_by_nodes_all_protocols(self):
        nodes = [ self.node_1, self.node_2]

        result = self.storage._get_ports_by_nodes(nodes, 1200, protocol=None)
        expected = (
            "SELECT node_id, node_ip, port, port_protocol, time FROM ports_scans where ( (node_id=? AND node_ip=?) OR (node_id=? AND node_ip=?) ) AND time > ?",
            [1, '127.0.0.1', 2, '127.0.0.2', 1200]
        )

        self.assertEqual(result, expected)

    def test__clear_security_scans(self):
        expected = "DELETE FROM security_scans WHERE sec_scan_start >= sec_scan_end OR sec_scan_start IS NULL OR sec_scan_end IS NULL",

        result = self.storage._clear_security_scans()

        self.assertEqual(result, expected)

    def test_init_schema(self):
        self.storage.execute = MagicMock()
        self.storage._clear_security_scans = MagicMock()
        self.storage._create_tables = MagicMock()

        self.storage.init_schema()
        self.storage.execute.assert_has_calls((call(self.storage._create_tables.return_value),
                                               call(self.storage._clear_security_scans.return_value)), any_order=False)
        self.storage._clear_security_scans.assert_called_once_with()
        self.storage._create_tables.assert_called_once_with()

    def test_save_node(self):
        node = MagicMock()
        self.storage._save_node = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_node(node=node, scan=self.scan)
        self.storage._save_node.assert_called_once_with(node=node, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_node())

    def test_save_nodes(self):
        nodes = MagicMock()
        self.storage._save_nodes = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_nodes(nodes=nodes, scan=self.scan)
        self.storage._save_nodes.assert_called_once_with(nodes=nodes, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_nodes())

    def test_get_nodes(self):
        self.storage._get_nodes = MagicMock()
        timestamp = MagicMock()
        pasttime = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1'),
            (2, '::1'),
        ))

        result = self.storage.get_nodes(pasttime=pasttime, timestamp=timestamp, scan=self.scan)

        self.storage._get_nodes.assert_called_once_with(pasttime=pasttime, timestamp=timestamp, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_nodes())

        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 2)

        self.assertEqual(result[0].ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].ip, ipaddress.ip_address('::1'))

    def test_get_vulnerabilities(self):
        self.storage._get_vulnerabilities = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, 1, '127.0.0.1', 17, 33, 2, 1, 'CVE-1', 5.5, 'output_1', 13, 33),
            (3, 2, '127.0.0.2', 6, 44, 3, 5, 'CVE-2', 4.4, 'output_2', 15, 44)
        ))

        result = self.storage.get_vulnerabilities(port=self.port_1, scan=self.scan, exploit=self.exploit_1)

        self.storage._get_vulnerabilities.assert_called_once_with(port=self.port_1, scan=self.scan, exploit=self.exploit_1)
        self.assertEqual(result[0].port, self.port_1)
        self.assertEqual(result[1].port, self.port_1)

        self.assertEqual(result[0].row_id, 33)
        self.assertEqual(result[1].row_id, 44)

        self.assertEqual(result[0].exploit, self.exploit_1)
        self.assertEqual(result[1].exploit, self.exploit_1)

        self.assertEqual(result[0].cvss, 5.5)
        self.assertEqual(result[1].cvss, 4.4)

        self.assertEqual(result[0].output, 'output_1')
        self.assertEqual(result[1].output, 'output_2')

        self.assertEqual(result[0].cve, 'CVE-1')
        self.assertEqual(result[1].cve, 'CVE-2')

        self.assertEqual(result[0].time, 13)
        self.assertEqual(result[1].time, 15)

    def test_get_nodes_by_scan(self):
        self.storage._get_scan_nodes = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1'),
            (2, '::1'),
        ))

        result = self.storage.get_nodes_by_scan(scan=self.scan)

        self.storage._get_scan_nodes.assert_called_once_with(scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_scan_nodes())

        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 2)

        self.assertEqual(result[0].scan, self.scan)
        self.assertEqual(result[1].scan, self.scan)

        self.assertEqual(result[0].ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].ip, ipaddress.ip_address('::1'))

    def test_save_port(self):
        port = MagicMock()
        self.storage._save_port = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_port(port=port, scan=self.scan)
        self.storage._save_port.assert_called_once_with(port=port, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_port())

    def test_save_ports(self):
        self.storage.scan = MagicMock()
        ports = MagicMock()
        self.storage._save_ports = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_ports(ports=ports, scan=self.storage.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_ports())

    def test_get_ports(self):
        self.storage.scan = MagicMock()
        self.storage._get_ports = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1', 20, 6),
            (2, '::1', 23, 17),
        ))

        result = self.storage.get_ports(pasttime=100, scan=self.storage.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_ports(pasttime=100))

        self.assertEqual(result[0].node.id, 1)
        self.assertEqual(result[1].node.id, 2)

        self.assertEqual(result[0].node.ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].node.ip, ipaddress.ip_address('::1'))

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)

        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)

    def test_get_ports_by_scan_and_node(self):
        self.storage.get_scan_id = MagicMock(return_value=87)
        self.storage._get_ports_by_node_and_scan = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, '127.0.0.1', 20, 6, 78, 67),
            (2, '127.0.0.2', 23, 17, 89, 98),
        ))

        result = self.storage.get_ports_by_scan_and_node(node=self.node_1, scan=self.scan)

        self.storage.execute.assert_called_once_with(self.storage._get_ports_by_node_and_scan(node=self.node_1,
                                                                                              scan=self.scan))

        self.assertEqual(result[0].node.id, 1)
        self.assertEqual(result[1].node.id, 2)

        self.assertEqual(result[0].row_id, 67)
        self.assertEqual(result[1].row_id, 98)

        self.assertEqual(result[0].node.ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].node.ip, ipaddress.ip_address('127.0.0.2'))

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)

        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)

    def test_save_security_scan(self):
        exploit = MagicMock()
        port = MagicMock()
        self.storage._save_security_scan = MagicMock()
        self.storage.execute = MagicMock()

        self.storage.save_security_scan(exploit=exploit, port=port, scan=self.scan)

        self.storage._save_security_scan.assert_called_once_with(exploit=exploit, port=port, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_security_scan())

    def test_save_security_scans(self):
        exploits = [self.exploit_1, self.exploit_2]
        port = [self.port_1, self.port_2, self.port_3]
        self.storage._save_security_scans = MagicMock()
        self.storage.execute = MagicMock()

        self.storage.save_security_scans(exploits=exploits, port=port, scan=self.scan)

        self.storage._save_security_scans.assert_called_once_with(exploits=exploits, port=port, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_security_scans())

    def test_get_security_scan_info(self):
        port = MagicMock()
        app = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (11, None, 'test_name', 1, '127.0.0.1', 6, 11, 10., 10.),
            (22, None, 'test_name_2', 2, '::1', 17, 22, None, None),
        ))
        self.storage._get_security_scan_info = MagicMock()

        result = self.storage.get_security_scan_info(port, app, scan=self.scan)

        self.storage._get_security_scan_info.assert_called_once_with(port=port, app=app, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_security_scan_info())

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

    def test_save_changes(self):
        changes = MagicMock()
        self.storage._save_changes = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_changes(changes=changes)
        self.storage._save_changes.assert_called_once_with(changes=changes)
        self.storage.execute.assert_called_once_with(self.storage._save_changes())

    def test_clear_security_scans(self):
        self.storage._clear_security_scans = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.clear_security_scans()
        self.storage._clear_security_scans.assert_called_once_with()
        self.storage.execute.assert_called_once_with(self.storage._clear_security_scans())

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
            (2, '127.0.0.2', 23, 17),
            (1, '127.0.0.1', 14, 17),
        ))

        nodes = [self.node_1, self.node_2]
        result = self.storage.get_ports_by_nodes(nodes, pasttime=pasttime, protocol=TransportProtocol.UDP)
        self.storage._get_ports_by_nodes.assert_called_once_with(nodes=nodes, portdetection_only=False, timestamp=78,
                                                                 protocol=TransportProtocol.UDP)
        self.storage.execute.assert_called_once_with(self.storage._get_ports_by_nodes())

        self.assertEqual(result[0].node, self.node_1)
        self.assertEqual(result[0].node.name, self.node_1.name)
        self.assertEqual(result[1].node, self.node_2)
        self.assertEqual(result[1].node.name, self.node_2.name)
        self.assertEqual(result[2].node, self.node_1)

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)
        self.assertEqual(result[2].number, 14)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)
        self.assertEqual(result[2].transport_protocol, TransportProtocol.UDP)

        self.assertEqual(result[0].scan.start, self.node_1.scan.start)
        self.assertEqual(result[1].scan.start, self.node_2.scan.start)
        self.assertEqual(result[2].scan.start, self.node_1.scan.start)

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

    def test__save_scan(self):
        result = self.storage._save_scan(scan=self.scan)
        expected = 'INSERT OR REPLACE INTO scans (protocol, scanner_name, scan_start, scan_end) VALUES (?, ?, ?, ?)', (17, 'test_name', 1, 17)
        self.assertCountEqual(result, expected)

    def test__update_scan(self):
        result = self.storage._update_scan(scan=self.scan)
        expected = 'UPDATE scans set scan_end = ? WHERE (protocol=? OR (? IS NULL AND protocol IS NULL)) AND scanner_name=? and scan_start=?', (17, 17, 17, 'test_name', 1)
        self.assertCountEqual(result, expected)

    def test__get_scans(self):
        result = self.storage._get_scans(protocol=TransportProtocol.ICMP, scanner_name='test_name', limit=3, offset=17)
        expected = 'SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE (protocol=? OR (? IS NULL AND protocol IS NULL)) AND '\
                   'scanner_name=? ORDER BY scan_end DESC, scan_start ASC LIMIT 3 OFFSET 17', (1, 1, 'test_name')
        self.assertCountEqual(result, expected)

    def test__get_scans_by_security_scan(self):
        result = self.storage._get_scans_by_security_scan(port=self.port_1, exploit=self.exploit_1, limit=3, offset=17)
        expected = 'SELECT scans.ROWID, protocol, scanner_name, scan_start, scan_end FROM scans LEFT JOIN security_scans ' \
                   'ON scans.ROWID = security_scans.scan_id WHERE node_id=? AND node_ip=? AND port_number=? AND ' \
                   '(port_protocol=? OR (? IS NULL AND port_protocol IS NULL))AND exploit_id=? AND exploit_app=? ' \
                   'AND exploit_name=?ORDER BY scan_end DESC, scan_start ASC LIMIT 3 OFFSET 17', \
                   (1, '127.0.0.1', 45, 17, 17, 14, 'test_app', 'test_name')
        self.assertCountEqual(result, expected)

    def test__get_scan(self):
        result = self.storage._get_scan(self.scan)
        expected = 'SELECT ROWID, protocol, scanner_name, scan_start, scan_end FROM scans WHERE (protocol=? OR (? IS NULL AND protocol IS NULL)) AND '\
                   'scanner_name=? AND scan_start=? LIMIT 1', (17, 17, 'test_name', 1)
        self.assertCountEqual(result, expected)

    def test_save_scan(self):
        scan = MagicMock()
        self.storage._save_scan = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_scan(scan=scan)
        self.storage._save_scan.assert_called_once_with(scan=scan)
        self.storage.execute.assert_called_once_with(self.storage._save_scan())

    def test_update_scan(self):
        scan = MagicMock()
        self.storage._update_scan = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.update_scan(scan=scan)
        self.storage._update_scan.assert_called_once_with(scan=scan)
        self.storage.execute.assert_called_once_with(self.storage._update_scan())

    def test_get_scan_id(self):
        self.storage.execute = MagicMock(return_value=((1, 17, 'test_name', 13, 19),))
        self.storage._get_scan = MagicMock()

        result = self.storage.get_scan_id(scan=self.scan)

        self.storage._get_scan.assert_called_once_with(scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_scan())
        self.assertEqual(result, 1)

    def test_get_scan_id_without_results(self):
        self.storage.execute = MagicMock(return_value=tuple())
        self.storage._get_scan = MagicMock()

        result = self.storage.get_scan_id(scan=self.scan)

        self.storage._get_scan.assert_called_once_with(scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_scan())
        self.assertIsNone(result)

    def test_get_scans(self):
        self.storage._get_scans = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, 17, 'test_name', 13, 19),
            (2, 6, 'test_name', 2, 18),
        ))

        result = self.storage.get_scans(scanner_name='test_name', protocol=TransportProtocol.UDP, amount=2)

        self.storage._get_scans.assert_called_once_with(scanner_name='test_name', protocol=TransportProtocol.UDP,
                                                        limit=2, offset=0)
        self.storage.execute.assert_called_once_with(self.storage._get_scans())

        self.assertEqual(result[0].protocol, TransportProtocol.UDP)
        self.assertEqual(result[0].start, 13)
        self.assertEqual(result[0].end, 19)

        self.assertEqual(result[1].protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].start, 2)
        self.assertEqual(result[1].end, 18)

    def test_get_scans_by_node(self):
        self.storage._get_scans_by_node = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, 17, 'test_name', 13, 19),
            (2, 6, 'test_name', 2, 18),
        ))

        result = self.storage.get_scans_by_node(node=self.node_1, scan=self.scan)

        self.storage._get_scans_by_node.assert_called_once_with(node=self.node_1, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._get_scans_by_node())

        self.assertEqual(result[0].protocol, TransportProtocol.UDP)
        self.assertEqual(result[0].start, 13)
        self.assertEqual(result[0].end, 19)

        self.assertEqual(result[1].protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].start, 2)
        self.assertEqual(result[1].end, 18)

    def test_get_scans_by_sec_scan(self):
        self.storage._get_scans_by_security_scan = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, 17, 'test_name', 13, 19),
            (2, 6, 'test_name', 2, 18),
        ))

        result = self.storage.get_scans_by_security_scan(port=self.port_1, exploit=self.exploit_1)

        self.storage._get_scans_by_security_scan.assert_called_once_with(port=self.port_1, exploit=self.exploit_1)
        self.storage.execute.assert_called_once_with(self.storage._get_scans_by_security_scan())

        self.assertEqual(result[0].protocol, TransportProtocol.UDP)
        self.assertEqual(result[0].start, 13)
        self.assertEqual(result[0].end, 19)

        self.assertEqual(result[1].protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].start, 2)
        self.assertEqual(result[1].end, 18)

    def test_get_scan_by_id(self):
        self.storage._get_scan_by_id = MagicMock()
        self.storage.execute = MagicMock(return_value=(
            (1, 17, 'test_name', 13, 19),
        ))

        result = self.storage.get_scan_by_id(15)

        self.storage._get_scan_by_id.assert_called_once_with(15)
        self.storage.execute.assert_called_once_with(self.storage._get_scan_by_id())

        self.assertEqual(result.protocol, TransportProtocol.UDP)
        self.assertEqual(result.start, 13)
        self.assertEqual(result.end, 19)

    def test_get_scan_by_id_no_results(self):
        self.storage._get_scan_by_id = MagicMock()
        self.storage.execute = MagicMock(return_value=tuple())

        result = self.storage.get_scan_by_id(15)

        self.assertEqual(result, None)

    def test__save_vulnerabilities(self):
        vulnerabilities = [self.vulnerability_1, self.vulnerability_2]
        self.storage.get_scan_id = MagicMock(return_value=16)

        expected = [
            ("INSERT OR REPLACE INTO vulnerabilities (scan_id, node_id, node_ip, port_protocol, port, " \
             "vulnerability_id, vulnerability_subid, cve, cvss, output, time) " \
             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
             (16, 1, '127.0.0.1', 17, 45, 14, 1, 'CVE-2017', 6.7, 'test_output_1', 13)),

            ("INSERT OR REPLACE INTO vulnerabilities (scan_id, node_id, node_ip, port_protocol, port, " \
             "vulnerability_id, vulnerability_subid, cve, cvss, output, time) " \
             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
             (16, 1, '127.0.0.1', 17, 45, 2, 2, 'CWE-14', 8.9, 'test_output_2', 98))
        ]

        result = self.storage._save_vulnerabilities(vulnerabilities, self.scan)

        self.storage.get_scan_id.assert_called_once_with(self.scan)
        self.assertEqual(result, expected)

    def test_save_vulnerabilities(self):
        vulnerabilities = MagicMock()
        self.storage._save_vulnerabilities = MagicMock()
        self.storage.execute = MagicMock()
        self.storage.save_vulnerabilities(vulnerabilities=vulnerabilities, scan=self.scan)
        self.storage._save_vulnerabilities.assert_called_once_with(vulnerabilities=vulnerabilities, scan=self.scan)
        self.storage.execute.assert_called_once_with(self.storage._save_vulnerabilities())
