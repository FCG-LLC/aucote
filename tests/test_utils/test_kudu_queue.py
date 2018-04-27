import ipaddress
from datetime import datetime
from unittest import TestCase
from unittest.mock import patch, MagicMock

from tests.time.test_utils import UTC
from utils.kudu_queue import KuduMsg, KuduQueue

utc = UTC()

class KuduMsgTest(TestCase):
    def setUp(self):
        self.kudu_msg = KuduMsg()

    def test_add_bool(self):
        self.kudu_msg.add_bool(True)

        self.assertEqual(self.kudu_msg._data, bytearray(b'\x01'))

    def test_add_byte(self):
        self.kudu_msg.add_byte(127)

        self.assertEqual(self.kudu_msg._data, bytearray(b'\x7f'))

    def test_add_short(self):
        self.kudu_msg.add_short(317)

        self.assertEqual(self.kudu_msg._data, bytearray(b'\x3d\x01'))

    def test_add_int(self):
        self.kudu_msg.add_int(3171545)

        self.assertEqual(self.kudu_msg._data, bytearray(b'\xd9\x64\x30\x00'))

    def test_add_long(self):
        self.kudu_msg.add_long(3171545)

        self.assertEqual(self.kudu_msg._data, bytearray(b'\xd9\x64\x30\x00\x00\x00\x00\x00'))

    def test_add_str(self):
        self.kudu_msg.add_str('Test')

        self.assertEqual(self.kudu_msg._data, bytearray(b'\x04\x00Test'))

    def test_add_datetime(self):
        self.kudu_msg.add_datetime(datetime(2016, 8, 16, 15, 23, 10, 183095, tzinfo=utc).timestamp())

        self.assertEqual(self.kudu_msg._data, bytearray(b'\xe7\xfb\xf2\x93V\x01\x00\x00'))

    def test_add_empty_datetime(self):
        self.kudu_msg.add_datetime(None)

        self.assertEqual(self.kudu_msg._data, bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))

    def test_add_ip(self):
        self.kudu_msg.add_ip(ipaddress.ip_address('127.0.0.1'))

        self.assertEqual(self.kudu_msg._data, bytearray(b'\x00\x64\xff\x9b\x00\x00\x00\x00'
                                                        b'\x00\x00\x00\x00\x7f\x00\x00\x01'))


class KuduQueueTest(TestCase):
    def setUp(self):
        self.address = '127.0.0.1'
        self.kudu_queue = KuduQueue(self.address)

    @patch('utils.kudu_queue.Socket')
    def test_connect(self, mock_kudu):
        mock_kudu.return_value = MagicMock()
        self.kudu_queue.connect()

        mock_kudu.return_value.connect.assert_called_once_with(self.address)

    def test_close(self):
        mock = MagicMock()
        self.kudu_queue._socket = mock
        self.kudu_queue.close()

        mock.close.assert_any_call()
        self.assertIsNone(self.kudu_queue._socket)

    def test_send(self):
        self.kudu_queue._socket = MagicMock()
        msg = KuduMsg()
        msg.add_bool(True)
        self.kudu_queue.send_msg(msg)

        self.kudu_queue._socket.send.assert_called_once_with(msg.data, 0)

    def test_send_non_blocking(self):
        self.kudu_queue._socket = MagicMock()
        msg = KuduMsg()
        msg.add_bool(True)
        self.kudu_queue.send_msg(msg, True)

        self.kudu_queue._socket.send.assert_called_once_with(msg.data, 1)
