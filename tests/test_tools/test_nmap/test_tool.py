from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel
from tools.nmap.tool import NmapTool
from utils.exceptions import ImproperConfigurationException


class NmapToolTest(TestCase):
    def setUp(self):
        self.exploit = Exploit()
        self.exploit.name = 'test_name'
        self.exploit.risk_level = RiskLevel.NONE

        self.exploit2 = Exploit()
        self.exploit2.name = 'test_name'
        self.exploit2.risk_level = RiskLevel.HIGH

        self.exploit_conf_args = Exploit()
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
        self.port = MagicMock()
        self.executor = MagicMock()
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
        self.assertEqual(port_scan_mock.call_count, 1)

    def test_enable(self):
        self.nmap_tool.executor = MagicMock()
        self.exploit2.name = 'test_name2'
        self.nmap_tool()
        self.assertEqual(self.nmap_tool.executor.add_task.call_count, 1)

    def test_single_mode(self):
        self.nmap_tool.executor = MagicMock()
        self.nmap_tool.config['services']['test_name']['singular'] = True
        self.exploit2.name = 'test_name2'
        self.nmap_tool()
        self.assertEqual(self.nmap_tool.executor.add_task.call_count, 2)

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

    @patch('tools.nmap.tool.cfg.get')
    def test_custom_args_dns_zone_transfer(self, mock_cfg):
        mock_cfg.return_value.cfg = ['test.host', 'test.host2']
        expected = ['dns-zone-transfer.domain=test.host', 'dns-zone-transfer.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_zone_transfer(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domains')

    @patch('tools.nmap.tool.cfg.get')
    def test_custom_args_dns_zone_transfer_exception(self, mock_cfg):
        mock_cfg.side_effect = KeyError

        self.assertRaises(ImproperConfigurationException, NmapTool.custom_args_dns_zone_transfer)


    @patch('tools.nmap.tool.VulnNmapScript')
    def test_improper_configure_args(self, vuln_scan_script):
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['services']['test_name2']['args'].side_effect = ImproperConfigurationException()
        self.nmap_tool()
        self.assertEqual(vuln_scan_script.call_count, 0)

    @patch('tools.nmap.tool.cfg.get')
    def test_custom_args_dns_srv_enum(self, mock_cfg):
        mock_cfg.return_value.cfg = ['test.host', 'test.host2']
        expected = ['dns-srv-enum.domain=test.host', 'dns-srv-enum.domain=test.host2']

        self.assertEqual(NmapTool.custom_args_dns_srv_enum(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domains')

    @patch('tools.nmap.tool.cfg.get')
    def test_custom_args_dns_srv_enumsrv_enum_exception(self, mock_cfg):
        mock_cfg.side_effect = KeyError

        self.assertRaises(ImproperConfigurationException, NmapTool.custom_args_dns_srv_enum)

    @patch('tools.nmap.tool.cfg.get')
    def test_custom_args_http_domino_enum_passwords(self, mock_cfg):
        mock_cfg.return_value.cfg = {"username": "test_usernm", "password": "test_passwd"}
        expected = "domino-enum-passwords.username='test_usernm',domino-enum-passwords.password=test_passwd"

        self.assertEqual(NmapTool.custom_args_http_domino_enum_passwords(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domino-http')

    @patch('tools.nmap.tool.cfg.get')
    def test_custom_args_http_domino_enum_passwords_exception(self, mock_cfg):
        mock_cfg.side_effect = KeyError

        self.assertRaises(ImproperConfigurationException, NmapTool.custom_args_http_domino_enum_passwords)