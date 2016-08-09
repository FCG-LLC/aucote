import unittest
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from fixtures.exploits import Exploit
from fixtures.exploits import Exploits
from structs import Port, TransportProtocol, Node
from scans.tasks import NmapPortScanTask
from tools.nmap.base import NmapScript


# TODO: This tests are complicated because of nesting and many mocking. Should be refactored.
@patch('database.serializer.Serializer.serialize_port_vuln', MagicMock)
class NmapPortScanTaskTest(unittest.TestCase):
    def setUp(self):
        self.exploit = Exploit()
        self.exploit.app = 'nmap'
        self.exploit.name = 'test'

        self.exploits = Exploits()
        self.exploits.add(self.exploit)

        self.port = Port()
        self.port.node = Node()
        self.port.node.ip = '127.0.0.1'

        self.script = NmapScript
        self.script.NAME = 'test'
        self.script.ARGS = 'test_args'

        self.port.transport_protocol = TransportProtocol.from_nmap_name("TCP")
        self.port.number = 22
        self.port.service_name = 'ssh'
        self.scan_task = NmapPortScanTask(self.port, [self.script])
        self.scan_task.exploits = self.exploits

        self.scan_task.kudu_queue = MagicMock()

        self.xml = '''<?xml version="1.0"?>
<script output="">
</script>
'''

    def test_tcp_scan(self):
        self.scan_task.call = MagicMock(side_effect=self.check_args_tcp)
        self.scan_task()

    def check_args_tcp(self, args):
        self.assertIn('-p', args)
        self.assertIn('22', args)
        self.assertIn('-sV', args)
        self.assertIn('--script', args)
        self.assertIn(self.script.NAME, args)
        self.assertIn('--script-args', args)
        self.assertIn(self.script.ARGS, args)
        self.assertIn(self.port.node.ip, args)

        return ElementTree.fromstring(self.xml)

    def test_udp_scan(self):
        self.scan_task._port.transport_protocol = TransportProtocol.from_nmap_name("UDP")
        self.scan_task.call = MagicMock(side_effect=self.check_args_udp)
        self.scan_task()

    def check_args_udp(self, args):
        self.assertIn('-sU', args)
        return self.check_args_tcp(args)
