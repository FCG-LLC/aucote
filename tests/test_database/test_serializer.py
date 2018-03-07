import datetime
import ipaddress
from unittest import TestCase
from unittest.mock import PropertyMock, patch, MagicMock

from database.serializer import Serializer
from fixtures.exploits import Exploit
from fixtures.exploits.exploit import ExploitMetric, ExploitCategory, ExploitTag
from scans.tcp_scanner import TCPScanner
from structs import Vulnerability, Port, Node, Scan, TransportProtocol, RiskLevel, VulnerabilityChangeType, \
    VulnerabilityChange, PortDetectionChange, PortScan, ScanContext
from tests.time.test_utils import UTC

utc = UTC()


class SerializerTest(TestCase):

    def setUp(self):
        self.serializer = Serializer()
        self.vuln = Vulnerability()

        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node.os = MagicMock()
        node.os.name_with_version = 'test_name_and_version'

        self.context = ScanContext(aucote=None, scan=TCPScanner)

        self.vuln.context = self.context

        port = Port(node=node, number=22, transport_protocol=TransportProtocol.TCP)
        port.protocol = 'ssh'

        port.scan = Scan()
        port.scan._start = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc).timestamp()
        port.when_discovered = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc).timestamp()

        self.vuln.port = port
        self.vuln.output = 'Test'

        self.exploit = Exploit(exploit_id=1)
        self.exploit.app = 'test_app'
        self.exploit.name = 'test_name'
        self.exploit.title = 'test_title'
        self.exploit.description = 'test_description'
        self.exploit.risk_level = RiskLevel.from_name('High')
        self.exploit.metric = ExploitMetric.VNC_INFO
        self.exploit.category = ExploitCategory.VULN
        self.exploit.tags = {ExploitTag.HTTP, ExploitTag.SSL, ExploitTag.HTTPS}

        self.vuln.exploit = self.exploit
        self.vuln.when_discovered = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc).timestamp()

    def test_vulnerability_serializer(self):

        result = self.serializer.serialize_port_vuln(self.vuln.port, self.vuln).data
        expected = bytearray(b'\x00\x00\xe7\xfb\xf2\x93V\x01\x00\x00\x16\x00 \x02\x7f\x00\x00\x01\x00\x00\x00\x00\x00'
                             b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00ssh\x00\x00\x00\x00\x06\xe7\xfb\xf2\x93V\x01'
                             b'\x00\x00\x04\x00Test\x01\x00\x00\x00\xe7\xfb\xf2\x93V\x01\x00\x00\x15\x00test_na'
                             b'me_and_version\x08\00VNC_INFO\x03\x00tcp\x08\x00test_app\t\x00test_name\x1a\x00\x00\x00'
                             b'\x00\x00\x00\x00')

        self.assertEqual(result, expected)

    def test_serialize_exploit(self):

        result = self.serializer.serialize_exploit(self.exploit).data
        expected = b'\x01\x00\x01\x00\x00\x00\x08\x00test_app\t\x00test_name\n\x00test_title\x10\x00test_description' \
                   b'\x03\x04\x00vuln\x1a\x00\x00\x00'

        self.assertEqual(result, expected)

    @patch('structs.PortDetectionChange.description', new_callable=PropertyMock)
    def test_serialize_portchange(self, output):
        output.return_value = 'test_output'
        scan_1 = Scan(start=1178603, end=17, protocol=TransportProtocol.UDP, scanner='test_name')
        scan_2 = Scan(start=187213, end=17, protocol=TransportProtocol.UDP, scanner='test_name')
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        port_1 = Port(node, transport_protocol=TransportProtocol.TCP, number=88)
        port_2 = Port(node, transport_protocol=TransportProtocol.TCP, number=88)
        previous_finding = PortScan(port=port_1, scan=scan_1, rowid=124)
        current_finding = PortScan(port=port_2, scan=scan_2, rowid=15)
        change = PortDetectionChange(current_finding=current_finding, change_time=124445,
                                     previous_finding=previous_finding)
        expected = bytearray(b'\x02\x00 \x02\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00X\x00\x06\x00\x00'
                             b'\x00\x00\x00\x00\x00\x00H\xe1j\x07\x00\x00\x00\x00\x01\x00\x00\x00\x00\xf8\r@F\x00'
                             b'\x00\x00\x00\xc8\xa4(\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00test_output')

        result = self.serializer.serialize_vulnerability_change(change).data

        self.assertEqual(result, expected)

    @patch('structs.PortDetectionChange.description', new_callable=PropertyMock)
    def test_serialize_vulnchange(self, output):
        output.return_value = 'test_output'
        scan_1 = Scan(start=1178603, end=17, protocol=TransportProtocol.UDP, scanner='test_name')
        scan_2 = Scan(start=187213, end=17, protocol=TransportProtocol.UDP, scanner='test_name')
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        port = Port(node, transport_protocol=TransportProtocol.TCP, number=88)
        exploit = Exploit(name="exploit_name", app="exploit_app", exploit_id=18)
        previous_finding = Vulnerability(output="test_output_1", exploit=exploit, port=port, subid=13, vuln_time=13456)
        previous_finding.scan = scan_1
        previous_finding.row_id = 124
        current_finding = Vulnerability(output="test_output_2", exploit=exploit, port=port, subid=13, vuln_time=6456345)
        current_finding.row_id = 15
        current_finding.scan = scan_2
        change = VulnerabilityChange(current_finding=current_finding, change_time=124445,
                                     previous_finding=previous_finding)
        expected = bytearray(b'\x02\x00 \x02\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00X\x00\x06\x12\x00'
                             b'\x00\x00\r\x00\x00\x00H\xe1j\x07\x00\x00\x00\x00\x01\x00\x00\x00\x00\x80R\xcd\x00\x00'
                             b'\x00\x00\x00\xa8\x01\xd4\x80\x01\x00\x00\x00\r\x00test_output_1\r\x00test_output_2\x15'
                             b'\x00Vulnerability changed')

        result = self.serializer.serialize_vulnerability_change(change).data

        self.assertEqual(result, expected)
