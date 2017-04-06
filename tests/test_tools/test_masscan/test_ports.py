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
        self.cfg = {
            'portdetection': {
                'network_scan_rate': 1000,
                'ports': {
                    'include': ['9'],
                    'exclude': []
                }
            },
            'tools': {
                'masscan': {
                    'cmd': 'test'
                }
            }
        }
        self.masscanports = MasscanPorts()
        node = Node(ip=ipaddress.ip_address(self.NODE_IP), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_arguments(self, mock_config):
        mock_config._cfg = {
            'portdetection': {
                'network_scan_rate': 1000,
                'ports': {
                    'include': ['T:17-45'],
                    'exclude': []
                }
            }
        }

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000', '--exclude-ports', 'U:0-65535', '--ports', 'T:17-45', self.NODE_IP]

        self.assertEqual(result, expected)
    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_string_ports(self, mock_config):
        mock_config._cfg = {
            'portdetection': {
                'network_scan_rate': 1000,
                'ports': {
                    'include': 'T:17-45',
                    'exclude': ''
                }
            }
        }

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000', '--exclude-ports', 'U:0-65535', '--ports', 'T:17-45', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_scan_ports_excluded(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.ports.exclude'] = ['45-89']

        result = self.masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000', '--exclude-ports', 'U:0-65535', '--ports', '9',
                    '--exclude-ports', '45-89', '127.0.0.1']
        self.assertEqual(result, expected)
