import ipaddress
from unittest.mock import MagicMock, patch

from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan, ScanContext
from tools.ssl.tool import SSLTool


class SSLToolTest(AsyncTestCase):
    def setUp(self):
        super(SSLToolTest, self).setUp()
        self.aucote = MagicMock()
        self.port = Port(node=Node(node_id=2, ip=ipaddress.ip_address('127.0.0.1')),
                         transport_protocol=TransportProtocol.UDP, number=16)
        self.exploit = Exploit(exploit_id=3)
        self.config = MagicMock()
        self.scan = Scan()
        self.context = ScanContext(aucote=self.aucote, scanner=None)
        self.tool = SSLTool(context=self.context, port=self.port, exploits=[self.exploit], config=self.config,
                            scan=self.scan,)

    @patch('tools.ssl.tool.SSLScriptTask')
    @gen_test
    async def test_call(self, mock_task):
        await self.tool()
        self.aucote.add_async_task.assert_called_once_with(mock_task.return_value)
        mock_task.assert_called_once_with(context=self.context, port=self.port, scan=self.scan,
                                          exploits=[self.aucote.exploits.find.return_value])
        self.aucote.exploits.find.assert_called_once_with('testssl', 'testssl')
