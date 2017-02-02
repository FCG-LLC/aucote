import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock

from structs import RiskLevel, Node, Port, Scan, PhysicalPort, BroadcastPort, StorageQuery
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
    def test_node_comparison_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node2 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        node1.name = 'test'
        node2.name = 'test'

        self.assertEqual(node1, node2)

    def test_equality_different_types(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node2 = MagicMock(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.assertNotEqual(node1, node2)

    def test_node_comparison_non_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node2 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=2)

        self.assertNotEqual(node1, node2)

    def test_node_comparison_none(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.assertNotEqual(node1, None)
        self.assertFalse(node1 == None)

    def test_hash(self):
        ip = MagicMock()
        id = MagicMock()

        expected = hash((id, ip))
        result = hash(Node(ip=ip, node_id=id))

        self.assertEqual(result, expected)

    def test_is_ipv6_on_ipv4(self):
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.assertFalse(node.is_ipv6)

    def test_is_ipv6_on_ipv6(self):
        node = Node(ip=ipaddress.ip_address('::1'), node_id=1)

        self.assertTrue(node.is_ipv6)


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
        port1.service_name = 'http'

        expected = "http://127.0.0.1:1"

        self.assertEqual(port1.url, expected)

    def test_get_url_ipv6(self):
        node1 = Node(ip=ipaddress.ip_address('::1'), node_id=1)
        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port1.service_name = 'http'

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
        self.assertEqual(result.service_name, port.service_name)
        self.assertEqual(result.service_version, port.service_version)
        self.assertEqual(result.transport_protocol, port.transport_protocol)
        self.assertEqual(result.vulnerabilities, port.vulnerabilities)
        self.assertEqual(result.when_discovered, port.when_discovered)


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

class StorageQueryTest(TestCase):
    def setUp(self):
        self.test_query = "test_query"
        self.args = ("test", "args")
        self.only_query = StorageQuery(self.test_query)
        self.query = StorageQuery(self.test_query, self.args)

    def test_init(self):
        self.assertEqual(self.query.lock._value, 0)

    def test_args(self):
        expected = (self.test_query, self.args)
        self.assertEqual(self.query.query, expected)

    def test_only_query(self):
        expected = (self.test_query,)
        self.assertEqual(self.only_query.query, expected)
