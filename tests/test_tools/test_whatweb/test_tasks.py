import ipaddress

from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from fixtures.exploits import Exploit
from scans.tcp_scanner import TCPScanner
from structs import Port, Node, TransportProtocol, Scan, Service, ScanContext
from tools.whatweb.base import WhatWebBase
from tools.whatweb.structs import WhatWebResult, WhatWebTarget, WhatWebPlugin
from tools.whatweb.tasks import WhatWebTask


class WhatWebTaskTest(AsyncTestCase):
    def setUp(self):
        super(WhatWebTaskTest, self).setUp()
        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        self.port = Port(node=self.node, number=19, transport_protocol=TransportProtocol.UDP)
        self.port.protocol = 'http'
        self.aucote = MagicMock()
        self.exploit = Exploit(app='whatweb', name='whatweb', exploit_id=1)
        self.scan = Scan()
        self.context = ScanContext(aucote=self.aucote, scanner=TCPScanner)
        self.task = WhatWebTask(port=self.port, context=self.context, exploits=[self.exploit], scan=self.scan)

    def test_init(self):
        self.assertIsInstance(self.task.command, WhatWebBase)

    def test_prepare_args(self):
        result = self.task.prepare_args()
        expected = 'http://127.0.0.1:19',
        self.assertEqual(result, expected)

    @patch('scans.task_mapper.TaskMapper')
    @patch('tools.whatweb.tasks.CommandTask.execute')
    @gen_test
    async def test_call(self, mock_call, task_mapper):
        plugin = WhatWebPlugin()
        plugin.version = ['7.8']
        plugin.name = 'PHP'

        target = WhatWebTarget()
        target.plugins = [plugin]

        call_result = WhatWebResult()
        call_result.targets = [target]

        mock_call.return_value = Future()
        mock_call.return_value.set_result(call_result)

        task_mapper.return_value.assign_tasks.return_value = Future()
        task_mapper.return_value.assign_tasks.return_value.set_result(MagicMock())

        self.task.aucote.task_mapper.assign_tasks.return_value = Future()
        self.task.aucote.task_mapper.assign_tasks.return_value.set_result(True)

        expected_service = Service(name='php', version='7.8', cpe='cpe:2.3:a:php:php:7.8:*:*:*:*:*:*:*')
        await self.task()

        called_services = task_mapper().assign_tasks.call_args[1]['port'].apps
        self.assertEqual(called_services[0].cpe, expected_service.cpe)

    @patch('tools.whatweb.tasks.CommandTask.__call__')
    @gen_test
    async def test_call_unknown_plugin(self, mock_call):
        plugin = WhatWebPlugin()
        plugin.version = ['7.8']
        plugin.name = 'UnKnOwN____Pl_ugi__Nam3'

        target = WhatWebTarget()
        target.plugins = [plugin]

        call_result = WhatWebResult()
        call_result.targets = [target]

        mock_call.return_value = Future()
        mock_call.return_value.set_result(call_result)

        await self.task()

        self.assertFalse(self.task.aucote.task_mapper.assign_tasks.called)

    @patch('tools.whatweb.tasks.CommandTask.__call__')
    @gen_test
    async def test_call_plugin_without_version(self, mock_call):
        plugin = WhatWebPlugin()

        target = WhatWebTarget()
        target.plugins = [plugin]

        call_result = WhatWebResult()
        call_result.targets = [target]

        mock_call.return_value = Future()
        mock_call.return_value.set_result(call_result)

        await self.task()

        self.assertFalse(self.task.aucote.task_mapper.assign_tasks.called)

    @patch('tools.whatweb.tasks.CommandTask.__call__')
    @gen_test
    async def test_call_without_result(self, mock_call):
        mock_call.return_value = Future()
        mock_call.return_value.set_result(None)

        await self.task()

        self.assertFalse(self.task.aucote.task_mapper.assign_tasks.called)
