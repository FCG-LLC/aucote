from unittest.mock import patch, MagicMock

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from scans.tools_scanner import ToolsScanner


class ToolsScannerTest(AsyncTestCase):
    def setUp(self):
        super(ToolsScannerTest, self).setUp()
        self.aucote = MagicMock()
        self.task = ToolsScanner(aucote=self.aucote, scan_only=False)

    @patch('scans.tools_scanner.Executor')
    @gen_test
    async def test_run_scripts(self, mock_executor):
        ports = [MagicMock(), MagicMock()]
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.task._get_topdis_nodes = MagicMock(return_value=Future())
        self.task._get_topdis_nodes.return_value.set_result(nodes)

        self.task.get_ports_for_scan = MagicMock(return_value=ports)

        await self.task()

        mock_executor.assert_called_once_with(aucote=self.task.aucote, ports=ports)
        self.task.get_ports_for_scan.assert_called_once_with(nodes)