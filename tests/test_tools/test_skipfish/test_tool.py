import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel, Port, Node, TransportProtocol, Scan
from tools.skipfish.tool import SkipfishTool


class SkipfishToolTest(TestCase):
    def setUp(self):
        self.exploit = Exploit(exploit_id=1)
        self.exploit.name = 'skipfish'
        self.exploit.risk_level = RiskLevel.NONE

        self.config = {}

        self.exploits = [self.exploit]
        self.port = Port(node=Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1')), number=3,
                         transport_protocol=TransportProtocol.TCP)
        self.port.scan = Scan(start=13, end=45)

        self.executor = MagicMock()
        self.skipfish_tool = SkipfishTool(executor=self.executor, exploits=self.exploits, port=self.port,
                                          config=self.config)

    @patch('tools.skipfish.tool.SkipfishScanTask')
    def test_call(self, skipfish_scan_mock):
        self.skipfish_tool()

        skipfish_scan_mock.assert_called_once_with(executor=self.executor, port=self.port,
                                                   exploit=self.executor.exploits.find.return_value)

    @patch('aucote_cfg.cfg.get', MagicMock(return_value=False))
    def test_disable(self):
        config = MagicMock()
        SkipfishTool(exploits=MagicMock(), port=MagicMock(is_ipv6=False), executor=self.executor, config=config)()

        self.assertEqual(config.get.call_count, 0)

    @patch('aucote_cfg.cfg.get', MagicMock(return_value=True))
    @patch('tools.skipfish.tool.SkipfishScanTask')
    def test_disable_ipv6(self, mock_scantask):
        config = MagicMock()
        SkipfishTool(exploits=MagicMock(), port=MagicMock(is_ipv6=True), executor=self.executor, config=config)()

        self.assertFalse(mock_scantask.called)
