import ipaddress
from unittest.mock import patch

from tornado.testing import AsyncTestCase, gen_test

from structs import Node, Scan
from tools.masscan import MasscanPorts
from utils import Config
from utils.exceptions import StopCommandException


class MasscanPortsTest(AsyncTestCase):
    """
    Test masscan port scanning.
    """

    NODE_IP = '127.0.0.1'

    def setUp(self):
        super(MasscanPortsTest, self).setUp()
        self.cfg = {
            'portdetection': {
                'tcp': {
                    'ports': {
                        'include': ['9'],
                        'exclude': [],
                    },
                    'scan_rate': 1000
                },
                'udp': {
                    'ports': {
                        'include': [],
                        'exclude': []
                    },
                    'scan_rate': 30
                }
            },
            'tools': {
                'masscan': {
                    'cmd': 'test',
                    'args': []
                }
            }
        }
        self.masscanports = MasscanPorts()
        node = Node(ip=ipaddress.ip_address(self.NODE_IP), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.masscan.ports.cfg', new_callable=Config)
    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @gen_test
    async def test_arguments(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['tools.masscan.args'] = ['test_additional_arg1', 'test_additional_arg2']
        cfg2._cfg = cfg._cfg

        result = await self.masscanports.prepare_args(self.nodes)
        expected = ['test_additional_arg1', 'test_additional_arg2', '--rate', '1000',
                    '--ports', 'T:9', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.masscan.ports.cfg', new_callable=Config)
    @gen_test
    async def test_no_scan_ports(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.include'] = []
        cfg2._cfg = cfg._cfg

        with self.assertRaises(StopCommandException):
            await self.masscanports.prepare_args(self.nodes)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.masscan.ports.cfg', new_callable=Config)
    @gen_test
    async def test_string_ports(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg2._cfg = cfg._cfg

        result = await self.masscanports.prepare_args(self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:9', self.NODE_IP]

        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.masscan.ports.cfg', new_callable=Config)
    @gen_test
    async def test_scan_ports_excluded(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['portdetection.tcp.ports.exclude'] = ['45-89']
        cfg2._cfg = cfg._cfg

        result = await self.masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000',
                    '--ports', 'T:9',
                    '--exclude-ports', 'T:45-89', '127.0.0.1']
        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.cfg', new_callable=Config)
    @patch('tools.masscan.ports.cfg', new_callable=Config)
    @gen_test
    async def test_scan_without_udp(self, cfg, cfg2):
        cfg._cfg = self.cfg
        cfg['portdetection.udp.ports.include'] = ['15']
        cfg['portdetection.udp.ports.exclude'] = ['34']
        masscanports = MasscanPorts(udp=False)
        cfg2._cfg = cfg._cfg

        result = await masscanports.prepare_args(nodes=self.nodes)
        expected = ['--rate', '1000', '--ports', 'T:9', '127.0.0.1']

        self.assertEqual(result, expected)
