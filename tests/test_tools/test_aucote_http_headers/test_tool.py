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

    @patch('tools.aucote_http_headers.tool.cfg.get', MagicMock(return_value='test'))
    @patch('tools.aucote_http_headers.tool.HeaderDefinitions')
    def test_load(self, mock_header):
        config = MagicMock()
        exploits = MagicMock()
        AucoteHttpHeadersTool.load(config=config, exploits=exploits)

        mock_header.assert_called_once_with('test', exploits)