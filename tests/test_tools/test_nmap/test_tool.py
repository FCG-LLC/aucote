import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel, Port, TransportProtocol, Node, Scan
from tools.nmap.tool import NmapTool
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
            'services': {
                'test_name': {
                    'args': 'test_args'
                },
                'test_name2': {
                    'args': MagicMock()
                }
            }
        }

        self.exploits = [self.exploit, self.exploit2]
        self.port = Port(number=13, transport_protocol=TransportProtocol.TCP,
                         node=Node(node_id=1,ip=ipaddress.ip_address('127.0.0.1')))

        self.port.scan = Scan(start=14, end=13)

        self.executor = MagicMock(storage=Storage(":memory:"))
        self.nmap_tool = NmapTool(executor=self.executor, exploits=self.exploits, port=self.port, config=self.config)

    @patch('tools.nmap.tool.VulnNmapScript')
    @patch('tools.nmap.tool.InfoNmapScript')
    @patch('tools.nmap.tool.NmapPortScanTask')
    def test_call(self, port_scan_mock, info_scan_script, vuln_scan_script):

        self.nmap_tool()
        info_scan_script.assert_called_once_with(exploit=self.exploit, port=self.port, name='test_name',
                                                 args='test_args')
        vuln_scan_script.assert_called_once_with(exploit=self.exploit2, port=self.port, name='test_name',
                                                 args='test_args')

        result = port_scan_mock.call_count
        expected = 1

        self.assertEqual(result, expected)

    def test_enable(self):
        self.exploit2.name = 'test_name2'
        self.nmap_tool()

        result = self.nmap_tool.executor.add_task.call_count
        expected = 1

        self.assertEqual(result, expected)

    def test_single_mode(self):
        self.nmap_tool.config['services']['test_name']['singular'] = True
        self.exploit2.name = 'test_name2'
        self.nmap_tool()

        result = self.nmap_tool.executor.add_task.call_count
        expected = 2

        self.assertEqual(result, expected)

    @patch('tools.nmap.tool.VulnNmapScript')
    def test_configurable_args(self, vuln_scan_script):
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['services']['test_name2']['args'].return_value = 'dynamic_conf_test'
        self.nmap_tool()
        vuln_scan_script.assert_called_once_with(exploit=self.exploit_conf_args, port=self.port, name='test_name2',
                                                 args='dynamic_conf_test')

    @patch('tools.nmap.tool.VulnNmapScript')
    @patch('tools.nmap.tool.InfoNmapScript')
    @patch('tools.nmap.tool.NmapPortScanTask')
    def test_exploits_with_this_same_scripts_name(self, port_scan_mock, info_scan_script, vuln_scan_script):
        """
        Test executing exploits with this same script name
        Args:
            port_scan_mock (MagicMock):
            info_scan_script (MagicMock):
            vuln_scan_script (MagicMock):

        Returns:

        """

        self.config['services']['test_name']['args'] = ['test', 'test2']
        self.nmap_tool()
        info_scan_script.assert_any_call(exploit=self.exploit, port=self.port, name='test_name',
                                                 args='test')
        info_scan_script.assert_any_call(exploit=self.exploit, port=self.port, name='test_name',
                                                 args='test2')

        self.assertEqual(info_scan_script.call_count, 2)
        self.assertEqual(port_scan_mock.call_count, 2)

    @patch('tools.base.cfg.get')
    def test_custom_args_dns_zone_transfer(self, mock_cfg):
        mock_cfg.return_value.cfg = ['test.host', 'test.host2']
        expected = ['dns-zone-transfer.domain=test.host', 'dns-zone-transfer.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_zone_transfer(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domains')

    @patch('tools.base.cfg.get')
    def test_custom_args_dns_check_zone(self, mock_cfg):
        mock_cfg.return_value.cfg = ['test.host', 'test.host2']
        expected = ['dns-check-zone.domain=test.host', 'dns-check-zone.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_check_zone(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domains')

    @patch('tools.nmap.tool.VulnNmapScript')
    def test_improper_configure_args(self, vuln_scan_script):
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['services']['test_name2']['args'].side_effect = ImproperConfigurationException()
        self.nmap_tool()

        self.assertFalse(vuln_scan_script.called)

    @patch('tools.base.cfg.get')
    def test_custom_args_dns_srv_enum(self, mock_cfg):
        mock_cfg.return_value.cfg = ['test.host', 'test.host2']
        expected = ['dns-srv-enum.domain=test.host', 'dns-srv-enum.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_srv_enum(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domains')

    @patch('tools.base.cfg.get')
    def test_custom_args_http_domino_enum_passwords(self, mock_cfg):
        mock_cfg.return_value.cfg = {"username": "test_usernm", "password": "test_passwd"}
        expected = "domino-enum-passwords.username='test_usernm',domino-enum-passwords.password=test_passwd"

        self.assertEqual(NmapTool.custom_args_http_domino_enum_passwords(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domino-http')
