from unittest.mock import patch, MagicMock, PropertyMock, call

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from scans.tools_scanner import ToolsScanner
from structs import TransportProtocol, Port
from utils import Config


class ToolsScannerTest(AsyncTestCase):
    def setUp(self):
        super(ToolsScannerTest, self).setUp()
        self.aucote = MagicMock()
        self.task = ToolsScanner(aucote=self.aucote, name='tools')
        self.task._init()

    @patch('scans.tools_scanner.Executor')
    @patch('scans.tools_scanner.cfg', new_callable=Config)
    @gen_test
    async def test_run_scripts(self, cfg, mock_executor):
        cfg['portdetection.tools.scan_nodes'] = True
        ports = [MagicMock(), MagicMock()]
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.task._get_nodes_for_scanning = MagicMock(return_value=Future())
        self.task._get_nodes_for_scanning.return_value.set_result(nodes)

        self.task.get_ports_for_scan = MagicMock(return_value=ports)
        self.task.get_last_scan_start = MagicMock()

        await self.task.run()

        mock_executor.assert_called_once_with(context=self.task.context, nodes=nodes, ports=ports)
        self.task.get_ports_for_scan.assert_called_once_with(nodes, timestamp=self.task.get_last_scan().start)

    @patch('scans.tools_scanner.Executor')
    @patch('scans.tools_scanner.cfg', new_callable=Config)
    @gen_test
    async def test_run_disable_nodes(self, cfg, mock_executor):
        cfg['portdetection.tools.scan_nodes'] = False
        ports = [MagicMock(), MagicMock()]
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.task._get_nodes_for_scanning = MagicMock(return_value=Future())
        self.task._get_nodes_for_scanning.return_value.set_result(nodes)

        self.task.get_ports_for_scan = MagicMock(return_value=ports)
        self.task.get_last_scan_start = MagicMock()

        await self.task.run()

        mock_executor.assert_called_once_with(context=self.task.context, nodes=None, ports=ports)
        self.task.get_ports_for_scan.assert_called_once_with(nodes, timestamp=self.task.get_last_scan().start)

    @gen_test
    async def test_run_disable_nodes_topdis_error(self):
        self.task._get_nodes_for_scanning = MagicMock(side_effect=ConnectionError)
        self.task.get_last_scan_start = MagicMock()

        await self.task.run()

        self.assertFalse(self.task.storage.save_scan.called)

    def test_get_ports_for_scan(self):
        nodes = [MagicMock(), MagicMock(), MagicMock()]
        ports = [
            Port(node=nodes[0], number=13, transport_protocol=TransportProtocol.UDP),
            Port(node=nodes[1], number=14, transport_protocol=TransportProtocol.UDP),
            Port(node=nodes[0], number=13, transport_protocol=TransportProtocol.UDP),
        ]
        expected = list(set(ports))
        self.task.storage.get_ports_by_nodes.return_value = ports

        result = self.task.get_ports_for_scan(nodes, timestamp=100)

        self.assertCountEqual(result, expected)
        self.task.storage.get_ports_by_nodes.assert_called_once_with(nodes=nodes, timestamp=100, protocol=None,
                                                                     portdetection_only=True)
