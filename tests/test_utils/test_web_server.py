import socket
from unittest import TestCase
from unittest.mock import MagicMock, patch

from utils.web_server import WebServer


class WebServerTest(TestCase):
    def setUp(self):
        self.port = MagicMock()
        self.host = MagicMock()
        self.aucote = MagicMock()
        self.web_server = WebServer(self.aucote, self.host, self.port)

    @patch('utils.web_server.bind_sockets')
    @patch('utils.web_server.IOLoop')
    @patch('utils.web_server.HTTPServer')
    def test_start(self, mock_server, mock_ioloop, sock_bind):
        self.web_server.start()

        sock_bind.assert_called_once_with(self.web_server.port, reuse_port=True, address=self.web_server.host)
        self.web_server.server.add_sockets.assert_called_once_with(sock_bind.return_value)
        self.assertEqual(self.web_server.server, mock_server.return_value)

    @patch('utils.web_server.IOLoop')
    def test_stop(self, mock_ioloop):
        server = MagicMock()
        self.web_server.server = server
        self.web_server.stop()

        mock_ioloop.current.return_value.stop.assert_called_once_with()
        server.stop.assert_called_once_with()
        self.assertIsNone(self.web_server.server)
