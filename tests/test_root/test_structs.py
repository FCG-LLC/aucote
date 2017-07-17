import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock

from cpe import CPE

from structs import RiskLevel, Node, Port, Scan, PhysicalPort, BroadcastPort, Service, CPEType
from structs import TransportProtocol


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
        id = MagicMock()

        expected = hash((id, ip))
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
        self.assertEqual(result.when_discovered, port.when_discovered)

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
        self.start = 13
        self.end = 14.6
        self.scan = Scan(start=self.start, end=self.end)

    def test_init(self):
        self.assertEqual(self.scan.start, self.start)
        self.assertEqual(self.scan.end, self.end)


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
        expected = "phy:wlan0"
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
        self.version = 'test_version'
        self.vendor = 'apache'
        self.product = 'http_server'
        self.version = '2.4\(23\)'
        self.cpe = 'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'.format(vendor=self.vendor,
                                                                                 product=self.product,
                                                                                 version=self.version)
        self.service = Service(self.name, self.version)
        self.service.cpe = self.cpe

    def test_init(self):
        self.assertEqual(self.name, self.service.name)
        self.assertEqual(self.version, self.service.version)

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
