import datetime
import ipaddress
from unittest import TestCase

from database.serializer import Serializer
from fixtures.exploits import Exploit
from structs import Vulnerability, Port, Node, Scan, TransportProtocol, RiskLevel
from tests.time.test_utils import UTC

utc = UTC()

class SerializerTest(TestCase):

    def setUp(self):
        self.serializer = Serializer()
        self.vuln = Vulnerability()

        node = Node()
        node.ip = ipaddress.ip_address('127.0.0.1')
        node.id = 1

        port = Port()
        port.node = node
        port.number = 22
        port.service_name = 'ssh'
        port.transport_protocol = TransportProtocol.from_nmap_name("TCP")
        port.scan = Scan()
        port.scan.start = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc)
        port.when_discovered = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc)

        self.vuln.port = port
        self.vuln.output = 'Test'

        self.exploit = Exploit()
        self.exploit.id = 1
        self.exploit.app = 'test_app'
        self.exploit.name = 'test_name'
        self.exploit.title = 'test_title'
        self.exploit.description = 'test_description'
        self.exploit.risk_level = RiskLevel.from_name('High')

        self.vuln.exploit = self.exploit
        self.vuln.when_discovered = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc)

    def test_vulnerability_serializer(self):

        msg = self.serializer.serialize_port_vuln(self.vuln.port, self.vuln)

        self.assertEqual(msg.data, bytearray(b'\x00\x00\xe7\xfb\xf2\x93V\x01\x00\x00\x16\x00 \x02\x7f\x00\x00\x01\x00'
                                              b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00ssh\x00\x00'
                                              b'\x00\x00\x06\xe7\xfb\xf2\x93V\x01\x00\x00\x04\x00Test\x01\x00\x00\x00'
                                              b'\xe7\xfb\xf2\x93V\x01\x00\x00'))

    def test_serialize_exploit(self):

        msg = self.serializer.serialize_exploit(self.exploit)

        self.assertEqual(msg.data, bytearray(b'\x01\x00\x01\x00\x00\x00\x08\x00test_app\t\x00test_name\n\x00test_title'
                                              b'\x10\x00test_description\x03'))
