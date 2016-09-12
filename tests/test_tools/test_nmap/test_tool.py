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
        config = MagicMock()
        executor = MagicMock()
        NmapTool(executor, MagicMock(), MagicMock(), config=config)()
        self.assertEqual(executor.add_task.call_count, 1)

    @patch('tools.nmap.tool.VulnNmapScript')
    def test_configurable_args(self, vuln_scan_script):
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['services']['test_name2']['args'].return_value = 'dynamic_conf_test'
        self.nmap_tool()
        vuln_scan_script.assert_called_once_with(exploit=self.exploit_conf_args, port=self.port, name='test_name2',
                                                 args='dynamic_conf_test')

    @patch('tools.nmap.tool.cfg.get')
    def test_customArgsDNSZoneTransfer(self, mock_cfg):
        mock_cfg.return_value='test.host'
        expected = 'dns-zone-transfer.domain=test.host'

        self.assertEqual(NmapTool.custom_args_dns_zone_transfer(), expected)
        mock_cfg.assert_called_once_with('tools.nmap.domain')

    @patch('tools.nmap.tool.cfg.get')
    def test_customArgsDNSZoneTransfer_exception(self, mock_cfg):
        mock_cfg.side_effect = KeyError

        self.assertRaises(ImproperConfigurationException, NmapTool.custom_args_dns_zone_transfer)


    @patch('tools.nmap.tool.VulnNmapScript')
    def test_improper_configure_args(self, vuln_scan_script):
        self.nmap_tool.exploits = [self.exploit_conf_args]
        self.config['services']['test_name2']['args'].side_effect = ImproperConfigurationException()
        self.nmap_tool()
        self.assertEqual(vuln_scan_script.call_count, 0)