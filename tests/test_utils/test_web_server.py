from unittest.mock import MagicMock, patch

from tornado.testing import AsyncTestCase, gen_test

from utils.web_server import WebServer


class WebServerThreadTest(AsyncTestCase):
    def setUp(self):
        super(WebServerThreadTest, self).setUp()
        self.port = MagicMock()
        self.host = MagicMock()
        self.aucote = MagicMock()
        self.path = ''
        self.web_server = WebServer(self.aucote, self.host, self.port, self.path)

    @patch('utils.web_server.bind_sockets')
    @patch('utils.web_server.HTTPServer')
    @gen_test
    async def test_run(self, mock_server, sock_bind):
        await self.web_server.run()

        sock_bind.assert_called_once_with(self.web_server.port, reuse_port=True, address=self.web_server.host)
        self.web_server.server.add_sockets.assert_called_once_with(sock_bind.return_value)
        self.assertEqual(self.web_server.server, mock_server.return_value)

    def test_stop(self):
        server = MagicMock()
        self.web_server.server = server
        self.web_server.stop()

        server.stop.assert_called_once_with()
        self.assertIsNone(self.web_server.server)
