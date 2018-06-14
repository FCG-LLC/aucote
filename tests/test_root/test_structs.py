import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock

from cpe import CPE
from tornado.testing import AsyncTestCase, gen_test

from structs import Node, Port, Scan, PhysicalPort, BroadcastPort, Service, CPEType, PortState, \
    VulnerabilityChangeType, VulnerabilityChange, PortDetectionChange, PortScan, ScanContext, Vulnerability
from structs import TransportProtocol
from fixtures.exploits import RiskLevel, Exploit


class TransportProtocolTest(TestCase):

    def test_transport_protocol_exception(self):
        self.assertRaises(ValueError, TransportProtocol.from_nmap_name, '')
        self.assertRaises(ValueError, TransportProtocol.from_iana, -1)

    def test_transport_protocol_from_nmap_name(self):
        result = TransportProtocol.from_nmap_name("TCP")
        expected = TransportProtocol.TCP

        self.assertEqual(result, expected)

    def test_transport_protocol_from_iana(self):
        result = TransportProtocol.from_iana(6)
        expected = TransportProtocol.TCP

        self.assertEqual(result, expected)


class RiskLevelTest(TestCase):
    def test_risk_level_exception(self):
        self.assertRaises(ValueError, RiskLevel.from_name, '')


class NodeTest(TestCase):
    def setUp(self):
        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

    def test_node_comparison_eq(self):
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.node.name = 'test'
        node.name = 'test'

        self.assertEqual(self.node, node)

    def test_equality_different_types(self):
        node = MagicMock(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.assertNotEqual(self.node, node)

    def test_node_comparison_non_eq(self):
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=2)

        self.assertNotEqual(self.node, node)

    def test_node_comparison_none(self):

        self.assertNotEqual(self.node, None)
        self.assertFalse(self.node == None)

    def test_hash(self):
        ip = MagicMock()
        id = -1

        expected = hash((4294967295, ip))
        result = hash(Node(ip=ip, node_id=id))

        self.assertEqual(result, expected)

    def test_is_ipv6_on_ipv4(self):
        self.assertFalse(self.node.is_ipv6)

    def test_is_ipv6_on_ipv6(self):
        node = Node(ip=ipaddress.ip_address('::1'), node_id=1)

        self.assertTrue(node.is_ipv6)

    def test_str(self):
        expected = "127.0.0.1[1]"
        result = str(self.node)
        self.assertEqual(result, expected)

    def test_repr(self):
        expected = "<1, 127.0.0.1>".format(id(Node))
        result = repr(self.node)
        self.assertEqual(result, expected)

    def test_node_id_none(self):
        self.node.id = None

        self.assertEqual(self.node.id, 0)


class PortTest(TestCase):
    def test_ports_comparison_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port2 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)

        self.assertEqual(port1, port2)

    def test_equality_different_types(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port2 = MagicMock(node=node1, number=1, transport_protocol=TransportProtocol.TCP)

        self.assertNotEqual(port1, port2)

    def test_ports_comparison_non_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port2 = Port(node=node1, number=1, transport_protocol=TransportProtocol.UDP)

        self.assertNotEqual(port1, port2)

    def test_ports_comparison_none(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.UDP)

        self.assertNotEqual(port1, None)
        self.assertFalse(port1 is None)

    def test_hash(self):
        transport_protocol = MagicMock()
        number = MagicMock()
        node = MagicMock()

        expected = hash((transport_protocol, number, node))
        result = hash(Port(transport_protocol=transport_protocol, number=number, node=node))

        self.assertEqual(result, expected)
        
    def test_is_ipv6(self):
        port = Port(node=MagicMock(), number=1, transport_protocol=MagicMock())

        self.assertEqual(port.is_ipv6, port.node.is_ipv6)

    def test_is_broadcast(self):
        port = BroadcastPort()

        self.assertTrue(isinstance(port, BroadcastPort))
        self.assertFalse(isinstance(port, PhysicalPort))

    def test_is_physical(self):
        port = PhysicalPort()

        self.assertFalse(isinstance(port, BroadcastPort))
        self.assertTrue(isinstance(port, PhysicalPort))

    def test_get_url(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port1.protocol = 'http'

        expected = "http://127.0.0.1:1"

        self.assertEqual(port1.url, expected)

    def test_get_url_ipv6(self):
        node1 = Node(ip=ipaddress.ip_address('::1'), node_id=1)
        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port1.protocol = 'http'

        expected = "http://[::1]:1"

        self.assertEqual(port1.url, expected)

    def test_get_url_http_proxy(self):
        node1 = Node(ip=ipaddress.ip_address('::1'), node_id=1)
        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port1.protocol = 'http-proxy'

        expected = "http://[::1]:1"

        self.assertEqual(port1.url, expected)

    def test_copy(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        port = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        result = port.copy()

        self.assertEqual(result, port)
        self.assertEqual(result.interface, port.interface)
        self.assertEqual(result.scan, port.scan)
        self.assertEqual(result.banner, port.banner)
        self.assertEqual(result.node, port.node)
        self.assertEqual(result.number, port.number)
        self.assertEqual(result.service.name, port.service.name)
        self.assertEqual(result.service.version, port.service.version)
        self.assertEqual(result.transport_protocol, port.transport_protocol)
        self.assertEqual(result.vulnerabilities, port.vulnerabilities)

    def test_in_range(self):
        parsed_ports = {
            TransportProtocol.TCP: {22, 80, 81, 82},
            TransportProtocol.UDP: {78, 79, 80, 90},
            TransportProtocol.SCTP: {1, 2, 18, 19, 20}
        }

        port = Port(node=None, transport_protocol=TransportProtocol.TCP, number=80)

        self.assertTrue(port.in_range(parsed_ports))

    def test_not_in_range(self):
        parsed_ports = {
            TransportProtocol.TCP: {22, 80, 81, 82},
            TransportProtocol.UDP: {78, 79, 80, 90},
            TransportProtocol.SCTP: {1, 2, 18, 19, 20}
        }

        port = Port(node=None, transport_protocol=TransportProtocol.SCTP, number=80)

        self.assertFalse(port.in_range(parsed_ports))


class ScanTest(TestCase):
    def setUp(self):
        self.scan = Scan(start=13, end=14.6, protocol=TransportProtocol.ICMP, scanner="test_scanner", rowid=16)

    def test_init(self):
        expected = {
            "_start": 13000,
            "_end": 14600,
            "_protocol": TransportProtocol.ICMP,
            "_scanner": "test_scanner",
            "rowid": 16
        }

        result = self.scan.__dict__

        self.assertDictEqual(result, expected)


class SpecialPortTest(TestCase):
    def setUp(self):
        self.physical = PhysicalPort()
        self.broadcast = BroadcastPort()

    def test_copy_physical(self):
        self.assertIsInstance(self.physical.copy(), PhysicalPort)

    def test_copy_broadcast(self):
        self.assertIsInstance(self.broadcast.copy(), BroadcastPort)


class PhysicalPortTest(TestCase):
    def setUp(self):
        self.port = PhysicalPort()
        self.port.interface = 'wlan0'

    def test_str(self):
        expected = "255.255.255.255:phy:wlan0"
        self.assertEqual(str(self.port), expected)


class BroadcastPortTest(TestCase):
    def setUp(self):
        self.port = BroadcastPort()

    def test_str(self):
        expected = "broadcast"
        self.assertEqual(str(self.port), expected)


class ServiceTest(TestCase):
    def setUp(self):
        self.name = 'test_name'
        self.vendor = 'apache'
        self.product = 'http_server'
        self.version = '2.4\(23\)'
        self.cpe = 'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'.format(vendor=self.vendor,
                                                                                 product=self.product,
                                                                                 version=self.version)
        self.service = Service(self.name, self.version)
        self.service.cpe = self.cpe

    def test_init(self):
        expected = {
            'name': 'test_name',
            'version': '2.4\(23\)',
            '_cpe': CPE('cpe:2.3:a:apache:http_server:2.4\(23\):*:*:*:*:*:*:*')
        }

        result = self.service.__dict__

        self.assertDictEqual(result, expected)

    def test_cpe_setter_and_getter(self):
        self.assertEqual(self.service.cpe, CPE(self.cpe))

    def test_vendor(self):
        self.assertEqual(self.service.cpe_vendor, self.vendor)

    def test_product(self):
        self.assertEqual(self.service.cpe_product, self.product)

    def test_vendor_without_cpe(self):
        self.service._cpe = None
        self.assertIsNone(self.service.cpe_vendor)

    def test_product_without_cpe(self):
        self.service._cpe = None
        self.assertIsNone(self.service.cpe_product)

    def test_escape_cpe(self):
        data = r""""!";#$%&'()+,/:<=>@test123[]^`{}~-"""
        expected = r"""\"\!\"\;\#\$\%\&\'\(\)\+\,\/\:\<\=\>\@test123\[\]\^\`\{\}\~\-"""

        result = self.service._escape_cpe(data)

        self.assertEqual(result, expected)

    def test_escape_cpe_with_space(self):
        data = "12 13"
        self.assertRaises(ValueError, self.service._escape_cpe, data)

    def test_unescape_cpe(self):
        data = r"""\"\!\"\;\#\$\%\&\'\(\)\+\,\/\:\<\=\>\@test123\[\]\^\`\{\}\~\-"""
        expected = r""""!";#$%&'()+,/:<=>@test123[]^`{}~-"""

        result = self.service._unescape_cpe(data)

        self.assertEqual(result, expected)

    def test_version(self):
        self.assertEqual(self.service.cpe_version, '2.4(23)')

    def test_build_cpe(self):
        vendor = 'Collective-Sense'
        product = 'aucote'
        version = '0.0.1(test)'

        result = self.service.build_cpe(product=product, vendor=vendor, version=version, part=CPEType.APPLICATION)
        expected = "cpe:2.3:a:collective\-sense:aucote:0.0.1\(test\):*:*:*:*:*:*:*"

        self.assertEqual(result, expected)

    def test_copy(self):
        service_copy = self.service.copy()

        self.assertEqual(self.service._cpe, service_copy._cpe)
        self.assertEqual(self.service.name, service_copy.name)
        self.assertEqual(self.service.version, service_copy.version)

    def test_validate_cpe_arguments_ios(self):
        version = "12.04e test"
        vendor = "*"
        product = "IOS"

        result = Service.validate_cpe_arguments(version=version, product=product, vendor=vendor)
        expected = "cisco", "ios", "12.04e"
        self.assertEqual(result, expected)


class PortStateTest(TestCase):

    def test_from_string(self):
        data = 'open|filtered'
        result = PortState.from_string(data)
        expected = PortState.OPEN_FILTERED

        self.assertEqual(result, expected)


class PortDetectionChangeTest(TestCase):
    def setUp(self):
        self.node = Node(node_id=13, ip=ipaddress.ip_address('127.0.0.5'))
        self.scan_1 = Scan(start=150421)
        self.scan_2 = Scan(start=159985)
        self.port_1 = Port(transport_protocol=TransportProtocol.TCP, number=80, node=self.node)
        self.port_1.scan = self.scan_1

        self.port_scan_1 = PortScan(port=self.port_1, scan=self.scan_1)

        self.port_2 = Port(transport_protocol=TransportProtocol.UDP, number=19, node=self.node)
        self.port_2.scan = self.scan_2

        self.port_scan_2 = PortScan(port=self.port_2, scan=self.scan_2)

        self.type = VulnerabilityChangeType.PORTDETECTION

        self.change_1 = PortDetectionChange(change_time=159986, current_finding=self.port_scan_1, previous_finding=None)
        self.change_2 = PortDetectionChange(change_time=159911, current_finding=None, previous_finding=self.port_scan_2)

    def test_init_change_1(self):
        expected = {
            'current_finding': self.port_scan_1,
            'previous_finding': None,
            'type': VulnerabilityChangeType.PORTDETECTION,
            'time': 159986,
            'score': 0,
            'vulnerability_id': 0,
            'vulnerability_subid': 0
        }

        result = self.change_1.__dict__

        self.assertDictEqual(result, expected)

    def test_init_change_2(self):
        expected = {
            'current_finding': None,
            'previous_finding': self.port_scan_2,
            'type': VulnerabilityChangeType.PORTDETECTION,
            'time': 159911,
            'score': 0,
            'vulnerability_id': 0,
            'vulnerability_subid': 0
        }

        result = self.change_2.__dict__

        self.assertDictEqual(result, expected)

    def test_node_ip(self):
        self.assertEqual(self.change_1.node_ip, ipaddress.ip_address('127.0.0.5'))
        self.assertEqual(self.change_2.node_ip, ipaddress.ip_address('127.0.0.5'))

    def test_node_id(self):
        self.assertEqual(self.change_1.node_id, 13)
        self.assertEqual(self.change_2.node_id, 13)

    def test_previous_scan_start(self):
        self.assertIsNone(self.change_1.previous_scan)
        self.assertEqual(self.change_2.previous_scan, 159985)

    def test_current_scan_start(self):
        self.assertEqual(self.change_1.current_scan, 150421)
        self.assertIsNone(self.change_2.current_scan)

    def test_output(self):
        self.assertEqual(self.change_1.description, "New port discovered")
        self.assertEqual(self.change_2.description, "Port disappeared")

    def test_port_number(self):
        self.assertEqual(self.change_1.port_number, 80)
        self.assertEqual(self.change_2.port_number, 19)

    def test_port_protocol(self):
        self.assertEqual(self.change_1.port_protocol, TransportProtocol.TCP)
        self.assertEqual(self.change_2.port_protocol, TransportProtocol.UDP)


class ScanContextTest(AsyncTestCase):
    def setUp(self):
        super(ScanContextTest, self).setUp()
        self.scan = MagicMock()
        self.aucote = MagicMock()
        self.context = ScanContext(aucote=self.aucote, scanner=self.scan)

    def test_add_task(self):
        task = MagicMock()
        self.context.add_task(task)

        self.assertIn(task, self.context.tasks)
        self.aucote.add_async_task.assert_called_once_with(task)

    def test_non_end_scan(self):
        self.context.tasks = [MagicMock(has_finished=MagicMock(return_value=False))]

        result = self.context.is_scan_end()

        self.assertFalse(result)

    def test_scan_end(self):
        self.context.tasks = [MagicMock(has_finished=MagicMock(return_value=True))]
        self.context.end = 0

        result = self.context.is_scan_end()

        self.assertTrue(result)


class VulnerabilityTest(TestCase):
    def setUp(self):
        self.exploit = Exploit(exploit_id=15, name='test_name', app='test_app', cve='CVE-2017-XXXX,CVE-2018-XXX',
                               cvss='4.6')

    def test_init(self):
        vulnerability = Vulnerability()

        self.assertEqual(vulnerability.cve, '')
        self.assertEqual(vulnerability.cvss, 0.)

    def test_init_with_exploit(self):
        vulnerability = Vulnerability(exploit=self.exploit)

        self.assertEqual(vulnerability.cve, 'CVE-2017-XXXX,CVE-2018-XXX')
        self.assertEqual(vulnerability.cvss, 4.6)

    def test_init_with_params(self):
        vulnerability = Vulnerability(exploit=self.exploit, cve='CVE-XXXX-XXXX', cvss=6.7)

        self.assertEqual(vulnerability.cve, 'CVE-XXXX-XXXX')
        self.assertEqual(vulnerability.cvss, 6.7)
