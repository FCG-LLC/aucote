import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock, call

from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit, RiskLevel
from structs import Port, TransportProtocol, Node, Scan, ScanContext
from tools.nmap.base import NmapScript
from tools.nmap.tool import NmapTool
from tools.nmap.parsers import NmapParser
from utils import Config
from utils.storage import Storage


class NmapToolTest(AsyncTestCase):
    def setUp(self):
        super(NmapToolTest, self).setUp()
        self.exploit = Exploit(exploit_id=1, name='test_name', risk_level=RiskLevel.NONE)

        self.exploit2 = Exploit(exploit_id=2, name='test_name', risk_level=RiskLevel.HIGH)

        self.exploit_conf_args = Exploit(exploit_id=3)
        self.exploit_conf_args.name = 'test_name2'
        self.exploit_conf_args.risk_level = RiskLevel.HIGH

        self.config = {
            'scripts': {
                'test_name': {
                    'args': 'test_args'
                },
                'test_name2': {
                    'args': MagicMock()
                }
            }
        }

        self.cfg = {
            'tools': {
                'nmap': {
                    'disable_scripts': [],
                },
                'common': {
                    'rate': 1337,
                    'http': {
                        'useragent': 'test_useragent'
                    }
                }
            },
            'config_filename': ''
        }

        self.exploits = [self.exploit, self.exploit2]
        self.port = Port(number=13, transport_protocol=TransportProtocol.TCP,
                         node=Node(node_id=1,ip=ipaddress.ip_address('127.0.0.1')))

        self.port.scan = Scan(start=14, end=13)
        self.port.protocol = 'test_service'

        self.aucote = MagicMock(storage=Storage(":memory:"))
        self.scan = Scan()
        self.context = ScanContext(aucote=self.aucote, scanner=None)
        self.nmap_tool = NmapTool(context=self.context, exploits=self.exploits, port=self.port, config=self.config,
                                  scan=self.scan)

    @patch('tools.nmap.tool.NmapVulnParser')
    @patch('tools.nmap.tool.NmapInfoParser')
    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.NmapPortScanTask')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_call(self, cfg, port_scan_mock, nmap_script, info_scan_script, vuln_scan_script):
        cfg._cfg = self.cfg

        await self.nmap_tool()
        nmap_script.has_calls((
            call(exploit=self.exploit, port=self.port, parser=info_scan_script(), name='test_name',args='test_args'),
            call(exploit=self.exploit2, port=self.port, parser=vuln_scan_script(), name='test_name', args='test_args')
        ))

        result = port_scan_mock.call_count
        expected = 1

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_enable(self, cfg):
        cfg._cfg = self.cfg
        self.exploit2.name = 'test_name2'
        await self.nmap_tool()

        result = self.nmap_tool.aucote.add_async_task.call_count
        expected = 1

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_single_mode(self, cfg):
        cfg._cfg = self.cfg
        self.nmap_tool.config['scripts']['test_name']['singular'] = True
        self.exploit2.name = 'test_name2'
        await self.nmap_tool()

        result = self.nmap_tool.aucote.add_async_task.call_count
        expected = 2

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.NmapVulnParser')
    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_configurable_args(self, cfg, nmap_script, vuln_parser):
        cfg._cfg = self.cfg
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['scripts']['test_name2']['args'].return_value = 'dynamic_conf_test'
        await self.nmap_tool()
        nmap_script.assert_called_once_with(exploit=self.exploit_conf_args, port=self.port, parser=vuln_parser(),
                                                 name='test_name2', args='dynamic_conf_test')

    @patch('tools.nmap.tool.NmapPortScanTask')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_exploits_with_this_same_scripts_name(self, cfg, port_scan_mock):
        """
        Test executing exploits with this same script name
        Args:
            port_scan_mock (MagicMock):

        Returns:

        """
        cfg._cfg = self.cfg

        self.config['scripts']['test_name']['args'] = ['test', 'test2']
        self.nmap_tool._get_tasks = MagicMock()
        self.nmap_tool._get_tasks.return_value = [
            NmapScript(exploit=self.exploit, parser=NmapParser, port=self.port, name='test_name', args='test'),
            NmapScript(exploit=self.exploit, parser=NmapParser, port=self.port, name='test_name', args='test2')
        ]

        await self.nmap_tool()
        self.assertEqual(port_scan_mock.call_count, 2)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_custom_args_dns_zone_transfer(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domains'] = ['test.host', 'test.host2']
        expected = ['dns-zone-transfer.domain=test.host', 'dns-zone-transfer.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_zone_transfer(), expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_custom_args_dns_check_zone(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domains'] = ['test.host', 'test.host2']
        expected = ['dns-check-zone.domain=test.host', 'dns-check-zone.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_check_zone(), expected)

    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_improper_configure_args(self, cfg, nmap_script):
        cfg._cfg = self.cfg
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['scripts']['test_name2']['args'].side_effect = KeyError('test.test2')
        await self.nmap_tool()

        self.assertFalse(nmap_script.called)

    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_disable_script_by_cfg(self, cfg, nmap_script):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['disable_scripts'] = ['test_name', 'test_name2']

        self.nmap_tool.exploits = [self.exploit_conf_args]
        await self.nmap_tool()

        self.assertFalse(nmap_script.called)

    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    @gen_test
    async def test_disable_script_by_internal_cfg(self, cfg, nmap_script):
        cfg._cfg = self.cfg
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.nmap_tool.config['disable_scripts'] = {'test_name', 'test_name2'}
        await self.nmap_tool()

        self.assertFalse(nmap_script.called)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_custom_args_dns_srv_enum(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domains'] = ['test.host', 'test.host2']
        expected = ['dns-srv-enum.domain=test.host', 'dns-srv-enum.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_srv_enum(), expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_custom_args_http_domino_enum_passwords(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domino-http'] = {"username": "test_usernm", "password": "test_passwd"}
        expected = "domino-enum-passwords.username='test_usernm',domino-enum-passwords.password=test_passwd"

        self.assertEqual(NmapTool.custom_args_http_domino_enum_passwords(), expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_custom_args_http_useragent(self, cfg):
        cfg._cfg = self.cfg
        expected = "http.useragent='test_useragent'"

        self.assertEqual(NmapTool.custom_args_http_useragent(), expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_custom_service_args(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'disable_scripts': []
                }
            }
        }
        custom_args = MagicMock(return_value="test_arg")
        self.config['services'] = {
            'test_service': {
                'args': custom_args
            }
        }
        self.nmap_tool.exploits = [self.exploit]

        self.nmap_tool.config = self.config
        result = self.nmap_tool._get_tasks()
        expected = "test_args,test_arg"

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].args, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_empty_custom_service_args(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'disable_scripts': []
                }
            }
        }
        self.nmap_tool.config = self.config
        self.nmap_tool.exploits = [self.exploit]

        result = self.nmap_tool._get_tasks()
        expected = "test_args"

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].args, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_rate_from_tools_common(self, cfg):
        cfg._cfg = {
            'tools': {
                'common': {
                    'rate': 1337
                }
            }
        }
        result = self.nmap_tool.rate
        expected = 1337

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_rate(self, cfg):
        cfg._cfg = {
            'tools': {
                'common': {
                    'rate': 1337
                },
                'nmap': {
                    'rate': 7331
                }
            }
        }
        result = self.nmap_tool.rate
        expected = 7331

        self.assertEqual(result, expected)

    def test_parse_nmap_ports_string(self):
        ports = "T:22,80-82,U:78-80,U:90,S:1-2,18-20"

        expected = {
            TransportProtocol.TCP: {22, 80, 81, 82},
            TransportProtocol.UDP: {78, 79, 80, 90},
            TransportProtocol.SCTP: {1, 2, 18, 19, 20}
        }

        result = self.nmap_tool.parse_nmap_ports(ports)

        self.assertEqual(result, expected)

    def test_ports_from_list(self):
        tcp = ['14', '16-18']
        udp = ['87', '34-36']
        sctp = ['19', '25-28']

        expected = {
            TransportProtocol.TCP: {14, 16, 17, 18},
            TransportProtocol.UDP: {87, 34, 35, 36},
            TransportProtocol.SCTP: {19, 25, 26, 27, 28}
        }

        result = NmapTool.ports_from_list(tcp=tcp, udp=udp, sctp=sctp)
        self.assertEqual(result, expected)

    def test_list_to_ports(self):
        tcp = [14, '16-18']
        udp = [87, '34-36']
        sctp = [19, '25-28']

        expected = 'T:14,16-18,U:87,34-36,S:19,25-28'
        result = NmapTool.list_to_ports_string(tcp=tcp, udp=udp, sctp=sctp)

        self.assertEqual(result, expected)
