from unittest import TestCase
from unittest.mock import MagicMock, patch

from threads.web_server_thread import WebServerThread


class WebServerThreadTest(TestCase):
    def setUp(self):
        self.port = MagicMock()
        self.host = MagicMock()
        self.aucote = MagicMock()
        self.web_server = WebServerThread(self.aucote, self.host, self.port)

    @patch('threads.web_server_thread.bind_sockets')
    @patch('threads.web_server_thread.IOLoop')
    @patch('threads.web_server_thread.HTTPServer')
    def test_start(self, mock_server, mock_ioloop, sock_bind):
        self.web_server.run()

        sock_bind.assert_called_once_with(self.web_server.port, reuse_port=True, address=self.web_server.host)
        self.web_server.server.add_sockets.assert_called_once_with(sock_bind.return_value)
        self.assertEqual(self.web_server.server, mock_server.return_value)

    @patch('threads.web_server_thread.IOLoop')
    def test_stop(self, mock_ioloop):
        server = MagicMock()
        self.web_server.server = server
        self.web_server.stop()

        mock_ioloop.current.return_value.stop.assert_called_once_with()
        server.stop.assert_called_once_with()
        self.assertIsNone(self.web_server.server)
