from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.aucote_http_headers.tool import AucoteHttpHeadersTool


class AucoteHttpHeadersToolTest(TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.exploits = MagicMock()
        self.port = MagicMock()
        self.config = MagicMock()
        self.tool = AucoteHttpHeadersTool(executor=self.executor, exploits=self.exploits, port=self.port,
                                          config=self.config)

    @patch('tools.aucote_http_headers.tool.AucoteHttpHeadersTask')
    def test_call(self, mock_task):
        self.assertIsNone(self.tool())

        mock_task.assert_called_once_with(executor=self.executor, port=self.port,
                                          exploit=self.exploits, config=self.config)