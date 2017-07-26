import ipaddress
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from structs import Node
from tools.common.port_scan_task import PortScanTask
from utils.exceptions import NonXMLOutputException, StopCommandException


class PortScanTaskTest(AsyncTestCase):
    
    def setUp(self):
        super(PortScanTaskTest, self).setUp()
        self.command = MagicMock()
        self.task = PortScanTask(self.command)
    
    def test_prepare_args(self):
        self.assertRaises(NotImplementedError, self.task.prepare_args, [])

    @gen_test
    def test_scan_ports_without_nodes(self):
        nodes = []
        result = yield self.task.scan_ports(nodes)
        expected = []

        self.assertEqual(result, expected)

    @patch('tools.common.port_scan_task.OpenPortsParser.parse')
    @gen_test
    def test_scan_ports(self, mock_parser):
        expected = MagicMock()

        mock_parser.return_value = expected
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.task.prepare_args = MagicMock()
        future_1 = Future()
        future_1.set_result(MagicMock())
        self.task.command.async_call.return_value = future_1
        result = yield self.task.scan_ports(nodes)

        self.assertEqual(result, expected)

    @gen_test
    def test_scan_ports_with_exception(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.task.prepare_args = MagicMock()
        self.task.command.async_call.side_effect = NonXMLOutputException()

        result = yield self.task.scan_ports(nodes)
        expected = []

        self.assertEqual(result, expected)

    @gen_test
    async def test_scan_ports_with_stop_task_exception(self):
        nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.task.prepare_args = MagicMock()
        self.task.prepare_args.side_effect = StopCommandException

        result = await self.task.scan_ports(nodes=nodes)
        expected = []
        self.assertEqual(result, expected)
