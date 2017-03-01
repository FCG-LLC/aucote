import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from structs import Node, Scan
from tools.nmap.ports import PortsScan
from utils import Config


class PortScanTest(TestCase):

    NO_PORTS_OUTPUT = """<?xml version="1.0"?>
<!-- masscan v1.0 scan -->
<?xml-stylesheet href="" type="text/xsl"?>
<nmaprun scanner="masscan" start="1470387319" version="1.0-BETA"  xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" />
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/></host>
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/></host>
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/></host>
<runstats>
<finished time="1470387330" timestr="2016-08-05 10:55:30" elapsed="13" />
<hosts up="2" down="0" total="2" />
</runstats>
</nmaprun>
    """

    NON_XML = b'''This is non xml output!'''

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def setUp(self, cfg):
        cfg._cfg = {
            'service': {
                'scans': {
                    'ports': {
                        'include': '55',
                        'exclude': ''
                    },
                    'network_scan_rate': 1030
                }
            },
            'tools': {
                'nmap': {
                    'cmd': 'nmap',
                    'scripts_dir': '',
                }
            }
        }
        self.cfg = cfg
        self.kudu_queue = MagicMock()
        self.scanner = PortsScan(ipv6=True, tcp=False, udp=False)
        node = Node(ip=ipaddress.ip_address('192.168.1.5'), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_scan_ports(self, cfg):
        cfg._cfg = self.cfg._cfg

        result = self.scanner.prepare_args(nodes=self.nodes)
        expected = ['-sV', '-Pn', '--script', 'banner', '-6', '-p', '55', '--max-rate', '1030',
                    '192.168.1.5']
        self.assertEqual(result, expected)

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_scan_ports_excluded(self, cfg):
        cfg._cfg = self.cfg._cfg
        self.cfg['service.scans.ports.exclude'] = '45-89'

        result = self.scanner.prepare_args(nodes=self.nodes)
        expected = ['-sV', '-Pn', '--script', 'banner', '-6', '-p', '55', '--max-rate', '1030',
                    '--exclude-ports', '45-89', '192.168.1.5']
        self.assertEqual(result, expected)

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments(self, mock_config):
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': {
                        'include': 'T:17-45',
                        'exclude': ''
                    }
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                },
                'nmap': {
                    'scripts_dir': 'test'
                }
            },
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '-Pn', '--script', 'banner', '-6', '--datadir', 'test', '-p', 'T:17-45', '--max-rate', '1000',
                    '192.168.1.5']

        self.assertEqual(result, expected)

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments_tcp(self, mock_config):
        self.scanner.tcp = True
        self.scanner.ipv6 = False
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': {
                        'include': 'T:17-45',
                        'exclude': ''
                    }
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                },
                'nmap': {
                    'scripts_dir': 'test'
                }
            },
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '-Pn', '--script', 'banner', '-sS', '--datadir', 'test', '-p', 'T:17-45', '--max-rate', '1000',
                    '192.168.1.5']

        self.assertEqual(result, expected)

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments_udp(self, mock_config):
        self.scanner.udp = True
        self.scanner.ipv6 = False
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': {
                        'include': 'T:17-45',
                        'exclude': ''
                    }
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                },
                'nmap': {
                    'scripts_dir': 'test'
                }
            },
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '-Pn', '--script', 'banner', '-sU', '--datadir', 'test', '-p', 'T:17-45', '--max-rate', '1000',
                    '192.168.1.5']

        self.assertEqual(result, expected)