from unittest import TestCase
from unittest.mock import MagicMock, patch

from tornado.testing import gen_test, AsyncTestCase
from structs import PhysicalPort, Scan, ScanContext
from tools.cve_search.tool import CVESearchTool


class CVESearchToolTest(AsyncTestCase):
    def setUp(self):
        super(CVESearchToolTest, self).setUp()
        self.aucote = MagicMock()
        self.exploits = MagicMock()
        self.port = MagicMock()
        self.config = MagicMock()
        self.node = MagicMock()
        self.scan = Scan()
        self.context = ScanContext(aucote=self.aucote, scan=None)
        self.tool = CVESearchTool(context=self.context, exploits=self.exploits, port=self.port, node=self.node,
                                  config=self.config, scan=self.scan)

    @patch('tools.cve_search.tool.CVESearchServiceTask')
    @gen_test
    async def test_call(self, mock_task):
        self.assertIsNone(await self.tool())

        mock_task.assert_called_once_with(context=self.context, port=self.port, scan=self.scan,
                                          exploits=[self.aucote.exploits.find.return_value])
        self.aucote.exploits.find.assert_called_once_with('cve-search', 'cve-search')

    @patch('tools.cve_search.tool.CVESearchServiceTask')
    @gen_test
    async def test_call_without_port(self, mock_task):
        self.tool.port = None
        await self.tool()
        self.assertIsInstance(mock_task.call_args_list[0][1]['port'], PhysicalPort)
        self.assertEqual(mock_task.call_args_list[0][1]['port'].node, self.node)
