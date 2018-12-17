import ipaddress
from os import getenv
from unittest import TestCase

from sqlite3 import Connection

from sqlite3 import connect
from psycopg2.extensions import connection
from unittest.mock import MagicMock, patch, call

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, Scan, Vulnerability, VulnerabilityChangeBase, \
    VulnerabilityChangeType, PortDetectionChange, PortScan, SecurityScan, NodeScan
from utils.storage import Storage
from utils.config import Config


class StorageTest(TestCase):
    SEL_SEC_SCAN = ("SELECT scan_id, exploit_id, exploit_app, exploit_name, node_id, node_ip, port_protocol, "
                     "port_number, sec_scan_start, sec_scan_end FROM security_scans", )
    SEL_NOD_SCAN = ("SELECT scan_id, node_id, node_ip, time from nodes_scans",)
    SEL_POR_SCAN = ("SELECT scan_id, node_id, node_ip, port, port_protocol, time from ports_scans",)
    SEL_CHANGE = ("SELECT type, vulnerability_id, vulnerability_subid, previous_id, current_id, time FROM changes", )
    SEL_SCANS = ("SELECT ROWID, scan_start, scan_end, protocol, scanner_name FROM scans",)
    SEL_VULNS = ("SELECT scan_id, node_id, node_ip, port_protocol, port, vulnerability_id, vulnerability_subid, cve, cvss, output, time FROM vulnerabilities", )

    def setUp(self):
        self.maxDiff = None
        self.storage = Storage(conn_string=getenv('AUCOTE_TEST_POSTGRES'))
        self.scan = Scan(start=1, end=17, protocol=TransportProtocol.UDP, scanner='test_name')

        self.scan_1 = Scan(rowid=56, protocol=TransportProtocol.UDP, scanner='test_name', start=13, end=19)
        self.scan_2 = Scan(rowid=79, protocol=TransportProtocol.UDP, scanner='test_name', start=2, end=18)
        self.scan_3 = Scan(rowid=80, protocol=TransportProtocol.UDP, scanner='test_name_2', start=20, end=45)
        self.scan_4 = Scan(rowid=78, protocol=TransportProtocol.TCP, scanner='portdetection', start=1, end=2)

        self.node_1 = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        self.node_1.name = 'test_node_1'
        self.node_1.scan = Scan(start=15)

        self.node_2 = Node(node_id=2, ip=ipaddress.ip_address('127.0.0.2'))
        self.node_2.name = 'test_node_2'
        self.node_2.scan = Scan(start=56)

        self.node_3 = Node(node_id=3, ip=ipaddress.ip_address('127.0.0.3'))
        self.node_3.name = 'test_node_3'
        self.node_3.scan = Scan(start=98)

        self.node_4 = Node(node_id=4, ip=ipaddress.ip_address('127.0.0.4'))
        self.node_4.name = 'test_node_4'
        self.node_4.scan = Scan(start=3)

        self.node_scan_1 = NodeScan(node=self.node_1, rowid=13, scan=self.scan_1, timestamp=15)
        self.node_scan_2 = NodeScan(node=self.node_2, rowid=15, scan=self.scan_1, timestamp=56)
        self.node_scan_3 = NodeScan(node=self.node_3, rowid=16, scan=self.scan_1, timestamp=98)
        self.node_scan_3 = NodeScan(node=self.node_3, rowid=17, scan=self.scan_2, timestamp=90)

        self.port_1 = Port(node=self.node_1, number=45, transport_protocol=TransportProtocol.UDP)
        self.port_1.scan = self.scan_1

        self.port_scan_1 = PortScan(port=self.port_1, scan=self.scan_1, timestamp=176, rowid=124)

        self.port_2 = Port(node=self.node_2, transport_protocol=TransportProtocol.UDP, number=65)
        self.port_2.scan = Scan(start=3, end=45)

        self.port_scan_2 = PortScan(port=self.port_2, scan=self.scan_1, timestamp=987, rowid=15)

        self.port_3 = Port(node=self.node_3, transport_protocol=TransportProtocol.ICMP, number=99)
        self.port_3.scan = Scan(start=43, end=180)

        self.port_scan_3 = PortScan(port=self.port_3, scan=self.scan_1, timestamp=619, rowid=13)

        self.port_4 = Port(node=self.node_1, number=80, transport_protocol=TransportProtocol.UDP)
        self.port_4.scan = self.scan_1

        self.port_scan_4 = PortScan(port=self.port_4, scan=self.scan_1, timestamp=650, rowid=480)

        self.port_5 = Port(node=self.node_4, number=22, transport_protocol=TransportProtocol.TCP)
        self.port_5.scan = self.scan_4

        self.exploit_1 = Exploit(exploit_id=14, name='test_name', app='test_app')
        self.exploit_2 = Exploit(exploit_id=2, name='test_name_2', app='test_app_2')
        self.exploit_3 = Exploit(exploit_id=56, name='test_name_2', app='test_app')
        self.exploit_4 = Exploit(exploit_id=0, name='portdetection', app='portdetection')

        self.security_scan_1 = SecurityScan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_1, scan_start=178,
                                            scan_end=851)
        self.security_scan_2 = SecurityScan(exploit=self.exploit_2, port=self.port_1, scan=self.scan_1, scan_start=109,
                                            scan_end=775)
        self.security_scan_3 = SecurityScan(exploit=self.exploit_3, port=self.port_1, scan=self.scan_2, scan_start=113,
                                            scan_end=353)
        self.security_scan_4 = SecurityScan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_3, scan_start=180,
                                            scan_end=222)
        self.security_scan_5 = SecurityScan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_2, scan_start=14,
                                            scan_end=156)
        self.security_scan_6 = SecurityScan(exploit=self.exploit_2, port=self.port_1, scan=self.scan_2, scan_start=56,
                                            scan_end=780)
        self.security_scan_7 = SecurityScan(exploit=self.exploit_4, port=self.port_5, scan=self.scan_4, scan_start=14,
                                            scan_end=890)

        self.vuln_change_1 = PortDetectionChange(change_time=124445, current_finding=self.port_scan_1,
                                                 previous_finding=self.port_scan_2)

        self.vuln_change_2 = PortDetectionChange(change_time=32434, current_finding=self.port_scan_2,
                                                 previous_finding=self.port_scan_3)

        self.vulnerability_1 = Vulnerability(port=self.port_1, output='test_output_1', exploit=self.exploit_1,
                                             cve='CVE-2017', cvss=6.7, subid=1, vuln_time=13, rowid=134,
                                             scan=self.scan_1)
        self.vulnerability_2 = Vulnerability(port=self.port_1, output='test_output_2', exploit=self.exploit_2,
                                             cve='CWE-14', cvss=8.9, subid=2, vuln_time=98, rowid=152,
                                             scan=self.scan_1)
        self.vulnerability_3 = Vulnerability(port=self.port_1, output='test_output_3', exploit=self.exploit_1,
                                             cve='CVE-2016', cvss=3.7, subid=2, vuln_time=15, rowid=153,
                                             scan=self.scan_2)
        self.vulnerability_4 = Vulnerability(port=self.port_1, output='test_output_4', exploit=self.exploit_2,
                                             cve='CWE-15', cvss=2.9, subid=1, vuln_time=124, rowid=169,
                                             scan=self.scan_2)

        self.vulnerability_5 = Vulnerability(port=self.port_5, output='', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=0, vuln_time=124, rowid=200,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_6 = Vulnerability(port=self.port_5, output='tftp', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=1, vuln_time=124, rowid=201,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_7 = Vulnerability(port=self.port_5, output='tftp server name', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=2, vuln_time=124, rowid=202,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_8 = Vulnerability(port=self.port_5, output='6.7.8', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=3, vuln_time=124, rowid=203,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_9 = Vulnerability(port=self.port_5, output='HERE IS TFTP\n\n\n > ', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=4, vuln_time=124, rowid=204,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_10 = Vulnerability(port=self.port_5, output='test:cpe', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=5, vuln_time=124, rowid=205,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_11 = Vulnerability(port=self.port_5, output='os name', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=6, vuln_time=124, rowid=206,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_12 = Vulnerability(port=self.port_5, output='os version', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=7, vuln_time=124, rowid=207,
                                             scan=self.scan_4, expiration_time=400)
        self.vulnerability_13 = Vulnerability(port=self.port_5, output='test:os:cpe', exploit=self.exploit_4,
                                             cve=None, cvss=None, subid=8, vuln_time=124, rowid=208,
                                             scan=self.scan_4, expiration_time=400)

    def prepare_tables(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()
        self.prepare_scans()
        self.prepare_nodes_scans()
        self.prepare_ports_scans()
        self.prepare_vulnerabilities()
        self.prepare_security_scans()

    def prepare_scans(self):
        self.storage.execute(("INSERT INTO scans(ROWID, protocol, scanner_name, scan_start, scan_end) "
                              "VALUES "
                              "(56, 17, 'test_name', 13, 19), "
                              "(80, 17, 'test_name_2', 20, 45), "
                              "(79, 17, 'test_name', 2, 18),"
                              "(78, 6,  'portdetection', 1, 2)",))

    def prepare_nodes_scans(self):
        self.storage.execute(("INSERT INTO nodes_scans (ROWID, scan_id, node_id, node_ip, time) VALUES "
                              "(13, 56, 1, '127.0.0.1', 15), "
                              "(15, 56, 2, '127.0.0.2', 56), "
                              "(16, 56, 3, '127.0.0.3', 98), "
                              "(17, 79, 3, '127.0.0.3', 90) "
                              "",))

    def prepare_ports_scans(self):
        self.storage.execute(('INSERT INTO ports_scans(ROWID, scan_id, node_id, node_ip, port, port_protocol, time) '
                              'VALUES '
                              "(124, 56, 1, '127.0.0.1', 45, 17, 176), "
                              "(480, 56, 1, '127.0.0.1', 80, 17, 650), "
                              "(13, 56, 3, '127.0.0.3', 99, 1, 619), "
                              "(15, 56, 2, '127.0.0.2', 65, 17, 987)",))

    def prepare_security_scans(self):
        self.storage.execute(("INSERT INTO security_scans(exploit_id, exploit_name, exploit_app, scan_id, node_id, "
                              "node_ip, port_number, port_protocol, sec_scan_start, sec_scan_end) VALUES "
                              "(14, 'test_name', 'test_app', 56, 1, '127.0.0.1', 45, 17, 178, 851), "
                              "(56, 'test_name_2', 'test_app', 79, 1, '127.0.0.1', 45, 17, 113, 353), "
                              "(14, 'test_name', 'test_app', 80, 1, '127.0.0.1', 45, 17, 180, 222), "
                              "(2, 'test_name_2', 'test_app_2', 56, 1, '127.0.0.1', 45, 17, 109, 775), "
                              "(14, 'test_name', 'test_app', 79, 1, '127.0.0.1', 45, 17, 14, 156), "
                              "(2, 'test_name_2', 'test_app_2', 79, 1, '127.0.0.1', 45, 17, 56, 780), "
                              "(0, 'portdetection', 'portdetection', 78, 4, '127.0.0.4', 22, 6, 14, 890)",))

    def prepare_vulnerabilities(self):
        self.storage.execute(("INSERT INTO vulnerabilities (ROWID, scan_id, node_id, node_ip, port_protocol, port, "
                              "vulnerability_id, vulnerability_subid, cve, cvss, output, time, expiration_time) VALUES "
                              "(134, 56, 1, '127.0.0.1', 17, 45, 14, 1, 'CVE-2017', 6.7, 'test_output_1', 13, 600),"
                              "(152, 56, 1, '127.0.0.1', 17, 45, 2, 2, 'CWE-14', 8.9, 'test_output_2', 98, 600),"
                              "(153, 79, 1, '127.0.0.1', 17, 45, 14, 2, 'CVE-2016', 3.7, 'test_output_3', 15, NULL),"
                              "(169, 79, 1, '127.0.0.1', 17, 45, 2, 1, 'CWE-15', 2.9, 'test_output_4', 124, 600), "
                              "(200, 78, 4, '127.0.0.4', 6, 22, 0, 0, NULL, NULL, '', 124, 400), "
                              "(201, 78, 4, '127.0.0.4', 6, 22, 0, 1, NULL, NULL, 'tftp', 124, 400), "
                              "(202, 78, 4, '127.0.0.4', 6, 22, 0, 2, NULL, NULL, 'tftp server name', 124, 400), "
                              "(203, 78, 4, '127.0.0.4', 6, 22, 0, 3, NULL, NULL, '6.7.8', 124, 400), "
                              "(204, 78, 4, '127.0.0.4', 6, 22, 0, 4, NULL, NULL, 'HERE IS TFTP\n\n\n > ', 124, 400), "
                              "(205, 78, 4, '127.0.0.4', 6, 22, 0, 5, NULL, NULL, 'test:cpe', 124, 400), "
                              "(206, 78, 4, '127.0.0.4', 6, 22, 0, 6, NULL, NULL, 'os name', 124, 400), "
                              "(207, 78, 4, '127.0.0.4', 6, 22, 0, 7, NULL, NULL, 'os version', 124, 400), "
                              "(208, 78, 4, '127.0.0.4', 6, 22, 0, 8, NULL, NULL, 'test:os:cpe', 124, 400)"
                              "",))

    def test_context_manager(self):
        with self.storage:
            self.assertTrue(True)

    def test_connect(self):
        self.storage.connect()

        self.assertIsInstance(self.storage.conn, connection)

    def test_close(self):
        self.storage.conn = connect(":memory:")
        self.storage.close()

        self.assertEqual(self.storage.conn, None)

    def test__create_table(self):
        result = self.storage._create_tables()
        expected = [
            ("CREATE TABLE IF NOT EXISTS security_scans (rowid SERIAL UNIQUE, scan_id int, exploit_id int, exploit_app text, "
              "exploit_name text, node_id BIGINT, node_ip text, port_protocol int, port_number int, sec_scan_start float, "
              "sec_scan_end float, PRIMARY KEY (scan_id, exploit_id, node_id, node_ip, port_protocol, port_number))",),

            ("CREATE TABLE IF NOT EXISTS ports_scans (rowid SERIAL UNIQUE, scan_id int, node_id BIGINT, node_ip text, port int, port_protocol int,"
              " time int, primary key (scan_id, node_id, node_ip, port, port_protocol))",),

            ('CREATE TABLE IF NOT EXISTS nodes_scans(rowid SERIAL UNIQUE, scan_id int, node_id BIGINT, node_ip text, time int, primary key (scan_id, node_id, node_ip))',),

            (
            'CREATE TABLE IF NOT EXISTS scans(rowid SERIAL UNIQUE, protocol int, scanner_name VARCHAR, scan_start int, scan_end int, UNIQUE '\
            '(protocol, scanner_name, scan_start))',),

            (
            'CREATE TABLE IF NOT EXISTS vulnerabilities(rowid SERIAL UNIQUE, scan_id int, node_id BIGINT, node_ip text, '\
            'port_protocol int, port int, vulnerability_id int, vulnerability_subid int, cve text, cvss text, '\
            'output text, time int, expiration_time int, primary key(scan_id, node_id, node_ip, port_protocol, port, '\
            'vulnerability_id, vulnerability_subid))',),

            (
                'CREATE TABLE IF NOT EXISTS changes(rowid SERIAL PRIMARY KEY, type int, vulnerability_id int, '
                'vulnerability_subid int, ' \
                'previous_id int null, current_id int null, time int, UNIQUE(type, vulnerability_id, ' \
                'vulnerability_subid, previous_id, current_id, time))',
            )
        ]

        self.assertCountEqual(result, expected)

    def test_cursor_property(self):
        self.assertEqual(self.storage.cursor, self.storage._cursor)

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

    @patch('utils.storage.time.time', MagicMock(return_value=134))
    def test_save_nodes(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(56, 1, '127.0.0.1', 134),
                    (56, 2, '127.0.0.2', 134),
                    (56, 3, '127.0.0.3', 134)]

        self.storage.save_nodes(nodes=[self.node_1, self.node_2, self.node_3], scan=self.scan_1)

        result = self.storage.execute(self.SEL_NOD_SCAN)

        self.assertEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=60))
    def test_get_nodes(self):
        self.prepare_tables()

        expected = [self.node_2, self.node_3, self.node_3]

        result = self.storage.get_nodes(pasttime=10, scan=self.scan_1)

        self.assertCountEqual(result, expected)

    def test_get_vulnerabilities(self):
        self.prepare_tables()

        expected = [self.vulnerability_1]

        result = self.storage.get_vulnerabilities(port=self.port_1, scan=self.scan_1, exploit=self.exploit_1)

        self.assertCountEqual(result, expected)

    def test_get_nodes_by_scan(self):
        self.prepare_tables()

        expected = [self.node_1, self.node_2, self.node_3]

        result = self.storage.get_nodes_by_scan(scan=self.scan_1)

        self.assertCountEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=167))
    def test_save_port(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(56, 1, '127.0.0.1', 45, 17, 167)]

        self.storage.save_port(port=self.port_1, scan=self.scan_1)

        result = self.storage.execute(self.SEL_POR_SCAN)

        self.assertEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=167))
    def test_save_ports(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(56, 1, '127.0.0.1', 45, 17, 167),
                    (56, 2, '127.0.0.2', 65, 17, 167),
                    (56, 3, '127.0.0.3', 99, 1, 167)]

        self.storage.save_ports(ports=[self.port_1, self.port_2, self.port_3], scan=self.scan_1)

        result = self.storage.execute(self.SEL_POR_SCAN)

        self.assertEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=1000))
    def test_get_ports(self):
        self.prepare_tables()

        expected = [self.port_scan_2.port, self.port_scan_3.port, self.port_scan_4.port]

        result = self.storage.get_ports(pasttime=400, scan=self.scan_1)

        self.assertCountEqual(result, expected)

    def test_get_ports_by_scan_and_node(self):
        self.prepare_tables()

        expected = [self.port_scan_1, self.port_scan_4]

        result = self.storage.get_ports_by_scan_and_node(node=self.node_1, scan=self.scan_1)

        self.assertCountEqual(result, expected)

    def test_save_security_scan(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(56, 14, 'test_app', 'test_name', 1, '127.0.0.1', 17, 45, 13.0, 19.0)]

        self.storage.save_security_scan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_1)

        result = self.storage.execute(self.SEL_SEC_SCAN)

        self.assertEqual(result, expected)

    def test_save_security_scan_twice(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()
        self.port_1.scan.start = None

        expected = [(56, 14, 'test_app', 'test_name', 1, '127.0.0.1', 17, 45, None, 19.0)]

        self.storage.save_security_scan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_1)

        result = self.storage.execute(self.SEL_SEC_SCAN)

        self.assertEqual(result, expected)

        self.port_1.scan.start = 13
        self.port_1.scan.end = None

        expected = [(56, 14, 'test_app', 'test_name', 1, '127.0.0.1', 17, 45, 13.0, 19.0)]

        self.storage.save_security_scan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_1)

        result = self.storage.execute(self.SEL_SEC_SCAN)

        self.assertEqual(result, expected)

    def test_save_security_scans(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(56, 14, 'test_app', 'test_name', 1, '127.0.0.1', 17, 45, 13.0, 19.0),
                    (56, 2, 'test_app_2', 'test_name_2', 1, '127.0.0.1', 17, 45, 13.0, 19.0),
                    (56, 56, 'test_app', 'test_name_2', 1, '127.0.0.1', 17, 45, 13.0, 19.0)]

        self.storage.save_security_scans(exploits=[self.exploit_1, self.exploit_2, self.exploit_3], port=self.port_1,
                                         scan=self.scan_1)

        result = self.storage.execute(self.SEL_SEC_SCAN)

        self.assertEqual(result, expected)

    def test_get_security_scan_info(self):
        self.prepare_tables()

        expected = [self.security_scan_1, self.security_scan_3, self.security_scan_5]

        result = self.storage.get_security_scan_info(self.port_1, 'test_app', scan=self.scan_1)

        self.assertCountEqual(result, expected)

    def test_save_changes(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(1, 0, 0, 15, 124, 124445), (1, 0, 0, 13, 15, 32434)]

        self.storage.save_changes(changes=[self.vuln_change_1, self.vuln_change_2])

        result = self.storage.execute(self.SEL_CHANGE)

        self.assertEqual(result, expected)

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

    def test_get_ports_by_nodes_without_nodes(self):
        expected = []

        result = self.storage.get_ports_by_nodes([])

        self.assertEqual(result, expected)

    @patch('utils.storage.time.time', MagicMock(return_value=1000))
    def test_get_ports_by_nodes(self):
        self.storage.nodes_limit = 2
        self.prepare_tables()

        expected = [self.port_scan_2.port, self.port_scan_4.port]

        result = self.storage.get_ports_by_nodes(nodes=[self.node_1, self.node_3, self.node_2], pasttime=400,
                                                 protocol=TransportProtocol.UDP)

        self.assertCountEqual(result, expected)

    def test_execute_query(self):
        query = "part_1", "arg_1", "arg_2"
        self.storage._cursor = MagicMock()
        self.storage._cursor.rowcount = 2
        self.storage.conn = MagicMock()

        result = self.storage.execute(query)
        self.storage.cursor.execute.assert_called_once_with("part_1", "arg_1", "arg_2")
        self.storage.cursor.fetchall.assert_called_once_with()
        self.assertEqual(result, self.storage.cursor.fetchall())

    def test_execute_query_list(self):
        queries = [("part_1", "arg_1", "arg_2"), ("part_2", "arg_3")]
        self.storage._cursor = MagicMock()
        self.storage._cursor.rowcount = 2
        self.storage.conn = MagicMock()

        self.storage.execute(queries)
        self.storage.cursor.execute.assert_has_calls(
            (call("part_1", "arg_1", "arg_2"),
             call("part_2", "arg_3")))

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

    def test_save_scan(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(1, 13, 19, 17, 'test_name')]
        self.storage.save_scan(scan=self.scan_1)
        result = self.storage.execute(self.SEL_SCANS)

        self.assertEqual(result, expected)

    def test_update_scan(self):
        self.prepare_tables()

        self.scan_1.end = 456
        self.storage.update_scan(self.scan_1)

        expected = [(456,)]

        result = self.storage.execute(("SELECT scan_end FROM scans WHERE ROWID=56",))

        self.assertEqual(result, expected)

    def test_get_scan_id(self):
        expected = 56
        result = self.storage.get_scan_id(self.scan_1)
        self.assertEqual(result, expected)

    def test_get_scan_id(self):
        self.prepare_tables()

        expected = self.scan_1.rowid
        self.scan_1.rowid = None

        result = self.storage.get_scan_id(self.scan_1)

        self.assertEqual(result, expected)

    def test_get_scan_id_without_results(self):
        self.prepare_tables()

        expected = None
        self.scan_1.rowid = None
        self.scan_1._scanner = None

        result = self.storage.get_scan_id(self.scan_1)

        self.assertEqual(result, expected)

    def test_get_scans(self):
        self.prepare_tables()

        result = self.storage.get_scans(scanner_name='test_name', protocol=TransportProtocol.UDP, amount=2)

        self.assertEqual([self.scan_1, self.scan_2], result)
        for obj in self.scan_1, self.scan_2:
            self.assertEqual(result[result.index(obj)].rowid, obj.rowid)

    def test_get_scans_by_node(self):
        self.prepare_tables()

        expected = [self.scan_1, self.scan_2]

        result = self.storage.get_scans_by_node(node=self.node_3, scan=self.scan_1)

        self.assertEqual(result, expected)

    def test_get_scans_by_sec_scan(self):
        self.prepare_tables()

        expected = [self.scan_3, self.scan_1, self.scan_2]

        result = self.storage.get_scans_by_security_scan(port=self.port_1, exploit=self.exploit_1)

        self.assertEqual(result, expected)

    def test_get_scans_by_sec_scan_second(self):
        self.prepare_tables()

        expected = [self.scan_2]

        result = self.storage.get_scans_by_security_scan(port=self.port_1, exploit=self.exploit_3)

        self.assertEqual(result, expected)

    def test_get_scan_by_id(self):
        self.prepare_tables()

        expected = self.scan_1

        result = self.storage.get_scan_by_id(56)

        self.assertEqual(result, expected)

    def test_get_scan_by_id_no_results(self):
        self.storage.connect()
        self.storage.init_schema()

        result = self.storage.get_scan_by_id(15)

        self.assertEqual(result, None)

    def test_save_vulnerabilities(self):
        self.storage.connect()
        self.storage.remove_all()
        self.storage.init_schema()

        expected = [(56, 1, '127.0.0.1', 17, 45, 14, 1, 'CVE-2017', '6.7', 'test_output_1', 13),
                    (56, 1, '127.0.0.1', 17, 45, 14, 2, 'CVE-2016', '3.7', 'test_output_3', 15)]

        self.storage.save_vulnerabilities(vulnerabilities=[self.vulnerability_1, self.vulnerability_3], scan=self.scan_1)

        result = self.storage.execute(self.SEL_VULNS)

        self.assertCountEqual(result, expected)

    def test_scans(self):
        self.prepare_tables()

        self.assertEqual(self.storage.scans(2, 0), [self.scan_3, self.scan_1])
        self.assertEqual(self.storage.scans(2, 1), [self.scan_2, self.scan_4])

    def ports_scans_by_scan(self):
        self.prepare_tables()

        expected = [self.port_scan_1, self.port_scan_2, self.port_scan_3, self.port_scan_4]

        result = self.storage.ports_scans_by_scan(self.scan_1)

    def test_expire_vulnerability(self):
        self.prepare_tables()

        result = self.storage.expire_vulnerability(self.vulnerability_3)

        self.assertEqual(result.expiration_time, 178)

    def test_active_vulnerabilities(self):
        self.prepare_tables()

        expected = [self.vulnerability_3]

        result = self.storage.active_vulnerabilities()

        self.assertEqual(result, expected)

    def test_expire_vulnerabilities(self):
        self.prepare_tables()

        expected = []

        self.storage.expire_vulnerabilities()
        result = self.storage.active_vulnerabilities()

        self.assertEqual(result, expected)

    def test_portdetection_vulns(self):
        self.prepare_tables()

        expected = {
            'name': 'tftp server name',
            'version': '6.7.8',
            'banner': 'HERE IS TFTP\n\n\n > ',
            'cpe': 'test:cpe',
            'protocol': 'tftp',
            'os_name': 'os name',
            'os_version': 'os version',
            'os_cpe': 'test:os:cpe'
        }
        result = self.storage.portdetection_vulns(self.vulnerability_5)

        self.assertEqual(result, expected)