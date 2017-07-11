import ipaddress
from unittest import TestCase
from unittest.mock import patch

from structs import Node, Scan
from tools.masscan import MasscanPorts
from utils import Config
from utils.exceptions import StopCommandException


class MasscanPortsTest(TestCase):
    """
    Test masscan port scanning.
    """

    NODE_IP = '127.0.0.1'

    def setUp(self):
        self.cfg = {
            'portdetection': {
                'tcp': {
                    'scan_rate': 1000,
                    'ports': {
                        'include': ['9'],
                        'exclude': [],
                    }
                },
                'udp': {
                    'scan_rate': 1000,
                    'ports': {
                        'include': [],
                        'exclude': [],
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
    def test_arguments(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.include'] = ['17-45']

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:17-45', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_no_scan_ports(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.include'] = []

        self.assertRaises(StopCommandException, self.masscanports.prepare_args, nodes=self.nodes)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_string_ports(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.include'] = ['17-45']

        result = self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:17-45', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_scan_ports_excluded(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.exclude'] = ['45-89']

        result = self.masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:9',
                    '--exclude-ports', 'T:45-89', '127.0.0.1']
        self.assertEqual(result, expected)

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    def test_scan_without_udp(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.udp.ports.include'] = ['15']
        cfg['portdetection.udp.ports.exclude'] = ['34']
        masscanports = MasscanPorts(udp=False)

        result = masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000', '--ports', 'T:9', '127.0.0.1']

        self.assertEqual(result, expected)
