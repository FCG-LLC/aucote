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

    @patch('utils.web_server.socket.socket.listen')
    @patch('utils.web_server.socket.socket.bind')
    @patch('utils.web_server.IOLoop')
    @patch('utils.web_server.HTTPServer')
    def test_start(self, mock_server, mock_ioloop, sock_bind, sock_listen):
        self.web_server.start()

        sock = mock_server.return_value.add_socket.call_args[0][0]

        self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 1)
        self.assertEqual(sock.proto, socket.IPPROTO_TCP)
        self.assertEqual(sock.family, socket.AF_INET)
        self.assertTrue(sock.type & socket.SOCK_STREAM)
        self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.EWOULDBLOCK), 0)
        sock_bind.assert_called_once_with((self.host, self.port))

    @patch('utils.web_server.IOLoop')
    def test_stop(self, mock_ioloop):
        server = MagicMock()
        self.web_server.server = server
        self.web_server.stop()

        mock_ioloop.current.return_value.stop.assert_called_once_with()
        server.stop.assert_called_once_with()
        self.assertIsNone(self.web_server.server)
