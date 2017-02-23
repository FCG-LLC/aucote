import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock, call

from fixtures.exploits import Exploit
from structs import RiskLevel, Port, TransportProtocol, Node, Scan
from tools.nmap.base import NmapScript
from tools.nmap.tool import NmapTool
from tools.nmap.parsers import NmapParser
from utils import Config
from utils.exceptions import ImproperConfigurationException
from utils.storage import Storage


class NmapToolTest(TestCase):
    def setUp(self):
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
                    'rate': 1337
                }
            },
            'service': {
                'scans': {
                    'useragent': 'test_useragent'
                }
            },
            'config_filename': ''
        }

        self.exploits = [self.exploit, self.exploit2]
        self.port = Port(number=13, transport_protocol=TransportProtocol.TCP,
                         node=Node(node_id=1,ip=ipaddress.ip_address('127.0.0.1')))

        self.port.scan = Scan(start=14, end=13)
        self.port.service_name = 'test_service'

        self.aucote = MagicMock(storage=Storage(":memory:"))
        self.nmap_tool = NmapTool(aucote=self.aucote, exploits=self.exploits, port=self.port, config=self.config)

    @patch('tools.nmap.tool.NmapVulnParser')
    @patch('tools.nmap.tool.NmapInfoParser')
    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.NmapPortScanTask')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_call(self, cfg, port_scan_mock, nmap_script, info_scan_script, vuln_scan_script):
        cfg._cfg = self.cfg

        self.nmap_tool()
        nmap_script.has_calls((
            call(exploit=self.exploit, port=self.port, parser=info_scan_script(), name='test_name',args='test_args'),
            call(exploit=self.exploit2, port=self.port, parser=vuln_scan_script(), name='test_name', args='test_args')
        ))

        result = port_scan_mock.call_count
        expected = 1

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_enable(self, cfg):
        cfg._cfg = self.cfg
        self.exploit2.name = 'test_name2'
        self.nmap_tool()

        result = self.nmap_tool.aucote.add_task.call_count
        expected = 1

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_single_mode(self, cfg):
        cfg._cfg = self.cfg
        self.nmap_tool.config['scripts']['test_name']['singular'] = True
        self.exploit2.name = 'test_name2'
        self.nmap_tool()

        result = self.nmap_tool.aucote.add_task.call_count
        expected = 2

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.NmapVulnParser')
    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_configurable_args(self, cfg, nmap_script, vuln_parser):
        cfg._cfg = self.cfg
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['scripts']['test_name2']['args'].return_value = 'dynamic_conf_test'
        self.nmap_tool()
        nmap_script.assert_called_once_with(exploit=self.exploit_conf_args, port=self.port, parser=vuln_parser(),
                                                 name='test_name2', args='dynamic_conf_test')

    @patch('tools.nmap.tool.NmapPortScanTask')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_exploits_with_this_same_scripts_name(self, cfg, port_scan_mock):
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

        self.nmap_tool()
        self.assertEqual(port_scan_mock.call_count, 2)

    @patch('tools.base.cfg', new_callable=Config)
    def test_custom_args_dns_zone_transfer(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domains'] = ['test.host', 'test.host2']
        expected = ['dns-zone-transfer.domain=test.host', 'dns-zone-transfer.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_zone_transfer(), expected)

    @patch('tools.base.cfg', new_callable=Config)
    def test_custom_args_dns_check_zone(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domains'] = ['test.host', 'test.host2']
        expected = ['dns-check-zone.domain=test.host', 'dns-check-zone.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_check_zone(), expected)

    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_improper_configure_args(self, cfg, nmap_script):
        cfg._cfg = self.cfg
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['scripts']['test_name2']['args'].side_effect = ImproperConfigurationException('test.test2')
        self.nmap_tool()

        self.assertFalse(nmap_script.called)

    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_disable_script_by_cfg(self, cfg, nmap_script):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['disable_scripts'] = ['test_name', 'test_name2']

        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.nmap_tool()

        self.assertFalse(nmap_script.called)

    @patch('tools.nmap.tool.NmapScript')
    @patch('tools.nmap.tool.cfg', new_callable=Config)
    def test_disable_script_by_internal_cfg(self, cfg, nmap_script):
        cfg._cfg = self.cfg
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.nmap_tool.config['disable_scripts'] = {'test_name', 'test_name2'}
        self.nmap_tool()

        self.assertFalse(nmap_script.called)

    @patch('tools.base.cfg', new_callable=Config)
    def test_custom_args_dns_srv_enum(self, cfg):
        cfg._cfg = self.cfg
        cfg._cfg['tools']['nmap']['domains'] = ['test.host', 'test.host2']
        expected = ['dns-srv-enum.domain=test.host', 'dns-srv-enum.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_srv_enum(), expected)

    @patch('tools.base.cfg', new_callable=Config)
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
