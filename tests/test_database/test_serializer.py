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

        node = Node(ip = ipaddress.ip_address('127.0.0.1'), node_id=1)

        port = Port(node=node, number=22, transport_protocol=TransportProtocol.TCP)
        port.service_name = 'ssh'

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

        self.vuln.exploit = self.exploit
        self.vuln.when_discovered = datetime.datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc).timestamp()

    def test_vulnerability_serializer(self):

        result = self.serializer.serialize_port_vuln(self.vuln.port, self.vuln).data
        expected = bytearray(b'\x00\x00\xe7\xfb\xf2\x93V\x01\x00\x00\x16\x00 \x02\x7f\x00\x00\x01\x00\x00\x00\x00\x00'
                             b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00ssh\x00\x00\x00\x00\x06\xe7\xfb\xf2\x93V\x01'
                             b'\x00\x00\x04\x00Test\x01\x00\x00\x00\xe7\xfb\xf2\x93V\x01\x00\x00')

        self.assertEqual(result, expected)

    def test_serialize_exploit(self):

        result = self.serializer.serialize_exploit(self.exploit).data
        expected = b'\x01\x00\x01\x00\x00\x00\x08\x00test_app\t\x00test_name\n\x00test_title\x10\x00test_description' \
                   b'\x03'

        self.assertEqual(result, expected)

    def test_vulnerability_deserializer(self):
        data = '0000bfa9b70259010000bd012002c0a8d21000000000000000000000a40000000c006d6963726f736f66742d64730000000006d4a7b702590100000000000000000000000000000000'

        result = self.serializer.deserialize_port_vuln(data)

        expected = {
            'server_ip1': None,
            'server_ip2': 3232289296,
            'port': 445,
            'prot':6,
            'vuln_id': 0,
            'node_id': 164,
            'scan_start': 1481809308095,
            'port_scan_start': 1481809307604,
            'service_name': 'microsoft-ds',
            'service_version': '',
            'service_banner': '',
            'vuln_output': '',
            'timestamp_bucket': 1481809260,
            'key': 2865786373124384746,
            'vuln_when_discovered': 0,
        }

        self.assertDictEqual(result, expected)
