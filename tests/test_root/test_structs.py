import ipaddress
from unittest import TestCase

from structs import RiskLevel, Node, Port
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
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')
        node2 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')

        self.assertEqual(node1, node2)

    def test_node_comparison_non_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')
        node2 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=2, name='test')

        self.assertNotEqual(node1, node2)

    def test_node_comparison_none(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')

        self.assertNotEqual(node1, None)
        self.assertFalse(node1 == None)


class PortTest(TestCase):
    def test_ports_comparison_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')

        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port2 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)

        self.assertEqual(port1, port2)

    def test_ports_comparison_non_eq(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')

        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.TCP)
        port2 = Port(node=node1, number=1, transport_protocol=TransportProtocol.UDP)

        self.assertNotEqual(port1, port2)

    def test_ports_comparison_none(self):
        node1 = Node(ip=ipaddress.ip_address('127.0.0.1'), id=1, name='test')
        port1 = Port(node=node1, number=1, transport_protocol=TransportProtocol.UDP)

        self.assertNotEqual(port1, None)
        self.assertFalse(port1 == None)
