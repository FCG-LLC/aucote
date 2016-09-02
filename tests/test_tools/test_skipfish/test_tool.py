from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel
from tools.skipfish.tool import SkipfishTool


class SkipfishToolTest(TestCase):
    def setUp(self):
        self.exploit = Exploit()
        self.exploit.name = 'skipfish'
        self.exploit.risk_level = RiskLevel.NONE

        self.config = {}

        self.exploits = [self.exploit]
        self.port = MagicMock()
        self.port.service_name = 'test'
        self.executor = MagicMock()
        self.skipfish_tool = SkipfishTool(executor=self.executor, exploits=self.exploits, port=self.port,
                                          config=self.config)

    @patch('tools.skipfish.tool.SkipfishScanTask')
    def test_call(self, skipfish_scan_mock):
        self.skipfish_tool()
        skipfish_scan_mock.assert_called_once_with(executor=self.executor, port=self.port)

    @patch('aucote_cfg.cfg.get', MagicMock(return_value=False))
    def test_disable(self):
        config = MagicMock()
        SkipfishTool(MagicMock(), MagicMock(), MagicMock(), config=config)()
        self.assertEqual(config.get.call_count, 0)
