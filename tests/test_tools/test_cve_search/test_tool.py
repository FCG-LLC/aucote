from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.cve_search.tool import CVESearchTool


class CVESearchToolTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.exploits = MagicMock()
        self.port = MagicMock()
        self.config = MagicMock()
        self.tool = CVESearchTool(aucote=self.aucote, exploits=self.exploits, port=self.port, config=self.config)

    @patch('tools.cve_search.tool.CVESearchServiceTask')
    def test_call(self, mock_task):
        self.assertIsNone(self.tool())

        mock_task.assert_called_once_with(aucote=self.aucote, port=self.port,
                                          exploits=[self.aucote.exploits.find.return_value])
        self.aucote.exploits.find.assert_called_once_with('cve-search', 'cve-search')

    @patch('tools.cve_search.tool.CVESearchServiceTask')
    def test_call_without_port(self, mock_task):
        self.tool.port = None
        self.tool()
        self.assertFalse(mock_task.called)
