import ipaddress
import subprocess
from unittest import TestCase
from unittest.mock import patch, MagicMock

from structs import Node, Scan
from tools.masscan import MasscanPorts
from utils import Config


class MasscanPortsTest(TestCase):
    """
    Test masscan port scanning.
    """

    NODE_IP = '127.0.0.1'

    def setUp(self):
        self.masscanports = MasscanPorts()
        node = Node(ip=ipaddress.ip_address(self.NODE_IP), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_arguments(self, mock_config):
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': 1000,
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

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000', '--ports', 'T:17-45', 'arg1', 'arg2', 'test', self.NODE_IP]

        self.assertEqual(result, expected)
