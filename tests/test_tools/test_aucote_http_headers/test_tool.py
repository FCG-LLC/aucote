from unittest import TestCase
from unittest.mock import MagicMock, patch

from tornado.testing import AsyncTestCase, gen_test

from tools.aucote_http_headers.tool import AucoteHttpHeadersTool


class AucoteHttpHeadersToolTest(AsyncTestCase):
    def setUp(self):
        super(AucoteHttpHeadersToolTest, self).setUp()
        self.aucote = MagicMock()
        self.exploits = MagicMock()
        self.port = MagicMock()
        self.config = MagicMock()
        self.tool = AucoteHttpHeadersTool(aucote=self.aucote, exploits=self.exploits, port=self.port,
                                          config=self.config)

    @patch('tools.aucote_http_headers.tool.AucoteHttpHeadersTask')
    @gen_test
    async def test_call(self, mock_task):
        self.assertIsNone(await self.tool())

        mock_task.assert_called_once_with(aucote=self.aucote, port=self.port,
                                          exploits=self.exploits, config=self.config)