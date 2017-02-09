from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.aucote_http_headers.tool import AucoteHttpHeadersTool


class AucoteHttpHeadersToolTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.exploits = MagicMock()
        self.port = MagicMock()
        self.config = MagicMock()
        self.tool = AucoteHttpHeadersTool(aucote=self.aucote, exploits=self.exploits, port=self.port,
                                          config=self.config)

    @patch('tools.aucote_http_headers.tool.AucoteHttpHeadersTask')
    def test_call(self, mock_task):
        self.assertIsNone(self.tool())

        mock_task.assert_called_once_with(executor=self.aucote, port=self.port,
                                          exploits=self.exploits, config=self.config)