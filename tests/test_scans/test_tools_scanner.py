from unittest.mock import patch, MagicMock, PropertyMock, call

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from scans.tools_scanner import ToolsScanner
from structs import TransportProtocol
from utils import Config


class ToolsScannerTest(AsyncTestCase):
    def setUp(self):
        super(ToolsScannerTest, self).setUp()
        self.aucote = MagicMock()
        self.task = ToolsScanner(aucote=self.aucote)

    @patch('scans.tools_scanner.Scan')
    @patch('scans.tools_scanner.Executor')
    @patch('scans.tools_scanner.cfg', new_callable=Config)
    @gen_test
    async def test_run_scripts(self, cfg, mock_executor, scan):
        cfg['portdetection.tools.scan_nodes'] = True
        ports = [MagicMock(), MagicMock()]
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.task._get_nodes_for_scanning = MagicMock(return_value=Future())
        self.task._get_nodes_for_scanning.return_value.set_result(nodes)

        self.task.get_ports_for_scan = MagicMock(return_value=ports)

        await self.task.run()

        mock_executor.assert_called_once_with(aucote=self.task.aucote, nodes=nodes, ports=ports, scan=scan())
        self.task.get_ports_for_scan.assert_called_once_with(nodes)

    @patch('scans.tools_scanner.Scan')
    @patch('scans.tools_scanner.Executor')
    @patch('scans.tools_scanner.cfg', new_callable=Config)
    @gen_test
    async def test_run_disable_nodes(self, cfg, mock_executor, scan):
        cfg['portdetection.tools.scan_nodes'] = False
        ports = [MagicMock(), MagicMock()]
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.task._get_nodes_for_scanning = MagicMock(return_value=Future())
        self.task._get_nodes_for_scanning.return_value.set_result(nodes)

        self.task.get_ports_for_scan = MagicMock(return_value=ports)

        await self.task.run()

        mock_executor.assert_called_once_with(aucote=self.task.aucote, nodes=None, ports=ports, scan=scan())
        self.task.get_ports_for_scan.assert_called_once_with(nodes)

    @patch('scans.tools_scanner.ToolsScanner.previous_scan', new_callable=PropertyMock)
    def test_get_ports_for_scan(self, mock_previous):
        nodes = [MagicMock(), MagicMock(), MagicMock()]
        mock_previous.return_value = 100
        ports = [
            MagicMock(),
            MagicMock(),
            MagicMock()
        ]
        self.task.storage.get_ports_by_nodes.return_value = ports

        result = self.task.get_ports_for_scan(nodes)

        self.assertEqual(result, ports)
        self.task.storage.get_ports_by_nodes.assert_called_once_with(nodes=nodes, timestamp=100, protocol=None)
