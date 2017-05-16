import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol
from tools.ssl.tool import SSLTool


class SSLToolTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.port = Port(node=Node(node_id=2, ip=ipaddress.ip_address('127.0.0.1')),
                         transport_protocol=TransportProtocol.UDP, number=16)
        self.exploit = Exploit(exploit_id=3)
        self.config = MagicMock()
        self.tool = SSLTool(aucote=self.aucote, port=self.port, exploits=[self.exploit], config=self.config)

    @patch('tools.ssl.tool.SSLScriptTask')
    def test_call(self, mock_task):
        self.tool()
        self.aucote.add_task.assert_called_once_with(mock_task.return_value)
        mock_task.assert_called_once_with(aucote=self.aucote, port=self.port,
                                          exploits=[self.aucote.exploits.find.return_value])
        self.aucote.exploits.find.assert_called_once_with('testssl', 'testssl')
