import ipaddress
from unittest import TestCase
from unittest.mock import patch

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
                    'tcp': {
                        'include': ['9'],
                        'exclude': [],
                    },
                    'udp': {
                        'include': [],
                        'exclude': []
                    }
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
                    'tcp': {
                        'include': ['17-45'],
                        'exclude': [],
                    },
                    'udp': {
                        'include': [],
                        'exclude': []
                    }
                }
            }
        }

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:17-45', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_string_ports(self, mock_config):
        mock_config._cfg = {
            'portdetection': {
                'network_scan_rate': 1000,
                'ports': {
                    'tcp': {
                        'include': ['17-45'],
                        'exclude': [],
                    },
                    'udp': {
                        'include': [],
                        'exclude': []
                    }
                }
            }
        }

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:17-45', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_scan_ports_excluded(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.ports.tcp.exclude'] = ['45-89']

        result = self.masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:9',
                    '--exclude-ports', 'T:45-89', '127.0.0.1']
        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_scan_without_udp(self, cfg):
        cfg._cfg = self.cfg
        masscanports = MasscanPorts(udp=False)

        result = masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000',
                    '--exclude-ports', 'U:0-65535',
                    '--ports', 'T:9', '127.0.0.1']

        self.assertEqual(result, expected)
