import ipaddress
from unittest.mock import MagicMock, patch

from tornado.testing import gen_test, AsyncTestCase

from structs import Node, Scan
from tools.nmap.ports import PortsScan
from utils import Config
from utils.exceptions import StopCommandException


class PortScanTest(AsyncTestCase):

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

    def setUp(self):
        super(PortScanTest, self).setUp()
        cfg = {
            'portdetection': {
                'tcp': {
                    'ports': {
                        'include': ['55'],
                        'exclude': [],
                    },
                    'scan_rate': 1030,
                    'host_timeout': '600'
                },
                'udp': {
                    'ports': {
                        'include': [],
                        'exclude': []
                    },
                    'scan_rate': 30,
                    'defeat_icmp_ratelimit': False,
                    'max_retries': 77
                },
                '_internal': {
                    'udp_retries': 2
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
        self.scanner = PortsScan(ipv6=True, tcp=True, udp=False)
        node = Node(ip=ipaddress.ip_address('192.168.1.5'), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_scan_ports(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(nodes=self.nodes)
        expected = ['-Pn', '-6', '-sS', '--host-timeout', '600', '-p', 'T:55', '--max-rate', '1030', '192.168.1.5']
        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_no_scan_ports(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.include'] = []
        cfg2._cfg = cfg._cfg

        with self.assertRaises(StopCommandException):
            await self.scanner.prepare_args(nodes=self.nodes)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_scan_ports_excluded(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.exclude'] = ['45-89']
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(nodes=self.nodes)
        expected = ['-Pn', '-6', '-sS', '--host-timeout', '600', '-p', 'T:55', '--exclude-ports', 'T:45-89',
                    '--max-rate', '1030', '192.168.1.5']
        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_arguments(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['tools.nmap.scripts_dir'] = 'test'
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(self.nodes)
        expected = ['-Pn', '-6', '-sS', '--host-timeout', '600', '--datadir', 'test', '-p', 'T:55',
                    '--max-rate', '1030', '192.168.1.5']

        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_arguments_tcp(self, cfg, cfg2):
        self.scanner.tcp = True
        self.scanner.ipv6 = False
        cfg._cfg = self.cfg
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(self.nodes)
        expected = ['-Pn', '-sS', '--host-timeout', '600', '-p', 'T:55', '--max-rate', '1030', '192.168.1.5']

        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_arguments_udp(self, cfg, cfg2):
        self.scanner.udp = True
        self.scanner.tcp = False
        self.scanner.ipv6 = False
        cfg._cfg = self.cfg
        cfg['portdetection.udp.ports.include'] = ['12-16']
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(self.nodes)
        expected = ['-Pn', '-sU', '--max-retries', '77',
                    '-p', 'U:12-16', '--max-rate', '30', '192.168.1.5']
        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_arguments_udp_defeat_icmp(self, cfg, cfg2):
        self.scanner.udp = True
        self.scanner.tcp = False
        self.scanner.ipv6 = False
        cfg._cfg = self.cfg
        cfg['portdetection.udp.ports.include'] = ['12-16']
        cfg['portdetection.udp.defeat_icmp_ratelimit'] = True
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(self.nodes)
        expected = ['-Pn', '--min-rate', '30', '--defeat-icmp-ratelimit', '-sU', '--max-retries', '77',
                    '-p', 'U:12-16', '--max-rate', '30', '192.168.1.5']
        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.nmap.ports.cfg', new_callable=Config)
    @gen_test
    async def test_string_ports(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg2._cfg = cfg._cfg

        result = await self.scanner.prepare_args(self.nodes)
        expected = ['-Pn', '-6', '-sS', '--host-timeout', '600', '-p', 'T:55', '--max-rate', '1030', '192.168.1.5']
        self.assertEqual(result, expected)
