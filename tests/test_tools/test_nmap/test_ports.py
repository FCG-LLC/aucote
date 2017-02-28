import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from structs import Node, Scan
from tools.nmap.ports import PortsScan
from utils import Config


class PortScanTest(TestCase):
    def setUp(self):
        self.kudu_queue = MagicMock()
        self.scanner = PortsScan()
        node = Node(ip = ipaddress.ip_address('192.168.1.5'), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments(self, mock_config):
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': 'T:17-45'
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                }
            }
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '--script', 'banner', '-6', '-p', 'T:17-45', '--max-rate', '1000', '192.168.1.5']

        self.assertEqual(result, expected)
