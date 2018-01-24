from threading import Thread, Event
from unittest import TestCase

from tempfile import mkdtemp

import socket
from unittest.mock import MagicMock, patch

import select

from os import path

from utils.tftp import TFTP, TFTPTimeoutError


class TFTPHelper(Thread):
    """
    TFTP test helper. It always bind to the 127.0.0.1 and free port (0).
    The current port is available via `self.port`
    """
    def __init__(self, host, port, put, request=b'', *args, **kwargs):
        super(TFTPHelper, self).__init__(*args, **kwargs)
        self.dst_port = port
        self.dst_host = host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.host, self.port = self.socket.getsockname()
        self.started = Event()
        self.put = put
        self.response = None
        self.request = request
    
    def run(self):
        self.started.set()
        self.socket.sendto(self.request, (self.dst_host, self.dst_port))

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
        self.helper.dst_port = port

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

    @patch('utils.tftp.time.time', MagicMock(return_value=114))
    def test_check_timeouts(self):
        self.maxDiff = None
        receiver = self.tftp._open_port('127.0.0.1', 0)
        self.tftp._receivers[receiver.fileno()] = receiver
        event_1 = Event()
        event_1.set()

        event_2 = Event()

        event_3 = Event()

        self.tftp._files = {
            '127.0.0.1': {
                'event': event_1,
                'time': 113,
                'exception': None,
                'size': 0
            },
            '127.0.0.2': {
                'event': event_2,
                'time': 115,
                'exception': None,
                'size': 0
            },
            '127.0.0.3': {
                'event': event_3,
                'time': 110,
                'exception': None,
                'size': 0,
                'receiver': receiver
            }
        }

        expected = {
            '127.0.0.1': {
                'event': event_1,
                'time': 113,
                'exception': None,
                'size': 0
            },
            '127.0.0.2': {
                'event': event_2,
                'time': 115,
                'exception': None,
                'size': 0
            }
        }

        self.tftp.check_timeouts()
        self.assertDictEqual(self.tftp._files['127.0.0.1'], expected['127.0.0.1'])
        self.assertDictEqual(self.tftp._files['127.0.0.2'], expected['127.0.0.2'])
        self.assertTrue(self.tftp._files['127.0.0.3']['event'].is_set())
        self.assertIsInstance(self.tftp._files['127.0.0.3']['exception'], TFTPTimeoutError)
        self.assertEqual(receiver.fileno(), -1)

    @patch('utils.tftp.time.time', MagicMock(return_value=114))
    def test_register_address(self):
        self.tftp.register_address('127.0.0.15', 117)

        self.assertIsInstance(self.tftp._files['127.0.0.15']['event'], Event)
        self.assertEqual(self.tftp._files['127.0.0.15']['time'], 231)
        self.assertEqual(self.tftp._files['127.0.0.15']['size'], 0)
        self.assertIsNone(self.tftp._files['127.0.0.15']['exception'])

    def test_get_file_with_exception(self):
        event = Event()
        event.set()

        self.tftp._files = {
            '127.0.0.1': {
                'event': event,
                'time': 113,
                'exception': Exception(),
                'size': 0
            },
        }

        with self.assertRaises(Exception):
            self.tftp.get_file('127.0.0.1')

    def test_get_file(self):
        event = Event()
        event.set()

        self.tftp._files = {
            '127.0.0.1': {
                'event': event,
                'time': 113,
                'exception': None,
                'size': 0,
                'path': 'tmp/test_path.tst'
            },
        }

        expected = 'tmp/test_path.tst'

        result = self.tftp.get_file('127.0.0.1')

        self.assertEqual(result, expected)

    def tearDown(self):
        if self.tftp._socket is not None:
            self.tftp._socket.close()
