import ipaddress
from unittest.mock import MagicMock, patch

from tornado.testing import AsyncTestCase, gen_test

from fixtures.exploits import Exploit
from structs import Node, Port, TransportProtocol, Scan
from tools.whatweb.tool import WhatWebTool


class WhatWebToolTest(AsyncTestCase):
    def setUp(self):
        super(WhatWebToolTest, self).setUp()
        self.aucote = MagicMock()
        self.exploit = Exploit(exploit_id=1)
        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        self.port = Port(node=self.node, transport_protocol=TransportProtocol.UDP, number=87)
        self.config = MagicMock()
        self.scan = Scan()
        self.tool = WhatWebTool(aucote=self.aucote, exploits=[self.exploit], port=self.port, config=self.config,
                                scan=self.scan)

    @patch('tools.whatweb.tool.WhatWebTask')
    @gen_test
    async def test_call(self, mock_task):
        await self.tool()
        mock_task.assert_called_once_with(aucote=self.aucote, port=self.port, scan=self.scan,
                                          exploits=[self.aucote.exploits.find.return_value])
        self.aucote.exploits.find.assert_called_once_with('whatweb', 'whatweb')
        self.aucote.add_async_task.assert_called_once_with(mock_task.return_value)
