from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel
from tools.nmap.tool import NmapTool


class NmapToolTest(TestCase):
    def setUp(self):
        self.exploit = Exploit()
        self.exploit.name = 'test_name'
        self.exploit.risk_level = RiskLevel.NONE

        self.exploit2 = Exploit()
        self.exploit2.name = 'test_name'
        self.exploit2.risk_level = RiskLevel.HIGH

        self.config = {
            'services': {
                'test_name': {
                    'args': 'test_args'
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

