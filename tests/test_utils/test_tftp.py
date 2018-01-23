from threading import Thread, Event
from unittest import TestCase

from tempfile import mkdtemp

import socket
from unittest.mock import MagicMock, patch

import select

from os import path

from utils.tftp import TFTP


class TFTPHelper(Thread):
    def __init__(self, host, port, put, request=b'', *args, **kwargs):
        super(TFTPHelper, self).__init__(*args, **kwargs)
        self.port = port
        self.host = host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.started = Event()
        self.put = put
        self.response = None
        self.request = request
    
    def run(self):
        self.started.set()
        self.socket.sendto(self.request, (self.host, self.port))

        self.response = self.socket.recvfrom(1024)


class TFTPTest(TestCase):

    def setUp(self):
        self.tmp_directory = mkdtemp()
        self.timeout = 178
        self.tftp = TFTP('127.0.0.1', 0, self.timeout, self.tmp_directory)
        self.tftp.start()
        self.host, self.port = self.tftp._socket.getsockname()
        self.helper = TFTPHelper(self.host, self.port, True)

    def test_start(self):
        timeout = int(self.tftp._socket.gettimeout())
        reuse = self.tftp._socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)

        self.assertEqual(timeout, self.timeout)
        self.assertEqual(reuse, 1)

    def test_listen(self):
        self.tftp._stop = True
        self.tftp._epoll = MagicMock()
        self.tftp.handle_new_client = MagicMock()
        self.tftp.check_timeouts = MagicMock()
        self.tftp._epoll.poll.return_value = [(self.tftp._socket.fileno(), select.EPOLLIN)]

        self.tftp.listen()

        self.tftp.handle_new_client.assert_called_once_with()
        self.tftp.check_timeouts.assert_called_once_with()
        self.tftp._epoll.close.assert_called_once_with()

    @patch('utils.tftp.time.time', MagicMock(return_value=114))
    def test_handle_new_client(self):
        self.tftp._epoll = MagicMock()
        event = Event()

        self.tftp._files = {
            '127.0.0.1': {
                'event': event,
                'time': 0,
                'exception': None,
                'size': 0
            }
        }
        expected = {
            '127.0.0.1': {
                'event': event,
                'filename': 'test_filename',
                'path': 'tmp/114_test_filename',
                'size': 0,
                'exception': None,
                'time': 0
            }
        }
        self.helper.request = b'\x01\x02test_filename\0'

        self.helper.start()
        self.tftp.handle_new_client()
        self.helper.join()

        receiver = self.tftp._files['127.0.0.1']['receiver']
        del self.tftp._files['127.0.0.1']['receiver']

        self.assertEqual(self.helper.response, (b'\x00\x04\x00\x00', (self.host, receiver.getsockname()[1])))
        self.assertDictEqual(self.tftp._files, expected)

        self.assertEqual(self.tftp._receivers[receiver.fileno()], receiver)

        self.tftp._epoll.register.assert_called_once_with(receiver.fileno())

    def test_receive_file(self):
        receiver = self.tftp._open_port('127.0.0.1', 0)
        host, port = receiver.getsockname()
        self.helper.port = port

        fd = receiver.fileno()
        self.tftp._epoll.register(fd)
        self.tftp._receivers[fd] = receiver
        event = Event()

        file_path = path.join(self.tmp_directory, 'tmp_file')

        self.tftp._files = {
            '127.0.0.1': {
                'event': event,
                'filename': 'test_filename',
                'path': file_path,
                'size': 0,
                'exception': None,
                'time': 0,
                'receiver': receiver
            }
        }

        with open(file_path, 'wb') as f:
            f.write(b'before_')

        self.helper.request = b'\x01\x02\x03\x04test_data'
        self.helper.start()
        self.tftp.receive_file(fd)

        self.helper.join()

        self.assertEqual(self.helper.response, (b'\x00\x04\x03\x04', ('127.0.0.1', port)))

        with open(file_path, 'rb') as f:
            self.assertEqual(f.read(), b'before_test_data')

    def tearDown(self):
        if self.tftp._socket is not None:
            self.tftp._socket.close()
