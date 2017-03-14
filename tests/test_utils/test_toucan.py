from unittest import TestCase
from unittest.mock import patch, MagicMock, call

import requests
from requests import Response

from utils import Config
from utils.exceptions import ToucanException, ToucanUnsetException, ToucanConnectionException
from utils.toucan import Toucan


class TestToucan(TestCase):

    def setUp(self):
        self.toucan = Toucan('test_host', '3000', 'test_prot')

    @patch('utils.toucan.requests.get')
    def test_get_404(self, mock_get):
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 404
        self.assertRaises(ToucanUnsetException, self.toucan.get, "test.key")

    @patch('utils.toucan.requests.get')
    @patch('utils.toucan.Toucan.MIN_RETRY_TIME', 0)
    def test_get_502(self, mock_get):
        mock_get.return_value = Response()
        mock_get.return_value.json = MagicMock(return_value={"message": "test_error"})
        mock_get.return_value.status_code = 502
        self.assertRaises(ToucanConnectionException, self.toucan.get, "test.key")

    @patch('utils.toucan.requests.get')
    def test_get_500(self, mock_get):
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 500
        self.assertRaises(ToucanException, self.toucan.get, "test.key")

    @patch('utils.toucan.requests.get')
    def test_get_toucan_error(self, mock_get):
        json_data = {
            'status': 'ERROR',
            'message': 'test_message'
        }
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = MagicMock(return_value=json_data)

        self.assertRaises(ToucanException, self.toucan.get, "test.key")

    @patch('utils.toucan.requests.get')
    @patch('utils.toucan.Toucan.MIN_RETRY_TIME', 0)
    def test_get_with_exception(self, mock_get):
        mock_get.side_effect = (requests.exceptions.ConnectionError, Exception)

        self.assertRaises(Exception, self.toucan.get, "test.key")
        self.assertEqual(mock_get.call_count, 2)

    @patch('utils.toucan.Toucan.MIN_RETRY_TIME', 1)
    @patch('utils.toucan.Toucan.MAX_RETRY_TIME', 4)
    @patch('utils.toucan.Toucan.MAX_RETRY_COUNT', 5)
    @patch('utils.toucan.time.sleep')
    @patch('utils.toucan.requests.get')
    def test_try_if_fail_decorator_time_exceeded(self, mock_get, mock_sleep):
        mock_get.side_effect = requests.exceptions.ConnectionError

        self.assertRaises(ToucanConnectionException, self.toucan.get, "test.key")
        mock_sleep.assert_has_calls([call(1), call(2), call(4), call(4), call(4)], True)

    @patch('utils.toucan.requests.get')
    def test_get_data(self, mock_get):
        expected = 'test_value'
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': expected
        }
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.get("test.key")

        self.assertEqual(result, expected)

    @patch('utils.toucan.requests.get')
    def test_get_multiple_data(self, mock_get):
        expected = {'test.key': 'test_value'}
        json_data = [{
            'status': 'OK',
            'key': '/aucote/test/key',
            'value': 'test_value'
        }]
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.get("test.key")

        self.assertEqual(result, expected)

    @patch('utils.toucan.requests.get')
    def test_get_non_dict_nor_list(self, mock_get):
        json_data = 5
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = MagicMock(return_value=json_data)

        self.assertRaises(ToucanException, self.toucan.get, 'test.key')

    @patch('utils.toucan.requests.put')
    def test_put_data(self, mock_put):
        expected = 'test_value'
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': expected
        }
        mock_put.return_value = Response()
        mock_put.return_value.status_code = 200
        mock_put.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.put("test.key", "test_value")

        self.assertEqual(result, expected)
        mock_put.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/test/key', json={'value': 'test_value'})

    @patch('utils.toucan.requests.put')
    @patch('utils.toucan.Toucan.MIN_RETRY_TIME', 0)
    def test_put_with_exception(self, mock_put):
        mock_put.side_effect = (requests.exceptions.ConnectionError(), Exception)

        self.assertRaises(Exception, self.toucan.put, "test.key", "test_value")
        self.assertEqual(mock_put.call_count, 2)

    def test_push_config_exists_without_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }
        self.toucan.put = MagicMock()
        self.toucan.get = MagicMock(side_effect=('exists', ToucanUnsetException))

        self.toucan.push_config(config, overwrite=False)
        self.assertFalse(self.toucan.put.called)

    def test_push_config_non_exists_without_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }
        self.toucan.put = MagicMock()
        self.toucan.get = MagicMock(side_effect=(ToucanUnsetException,))

        self.toucan.push_config(config, overwrite=False)
        self.toucan.put.assert_called_once_with('test.key.test_key', 'test_value')

    def test_push_config_with_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }
        self.toucan.put = MagicMock()

        self.toucan.push_config(config, overwrite=True)
        self.toucan.put.assert_called_once_with('test.key.test_key', 'test_value')

    def test_prepare_config(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                },
                'other_key': 'test'
            }
        }
        self.toucan.put = MagicMock()

        result = self.toucan.prepare_config(config)
        expected = {
            'test.key.test_key': 'test_value',
            'test.other_key': 'test'
        }
        self.assertEqual(result, expected)

    @patch('utils.toucan.requests.put')
    def test_put_special_key_data(self, mock_put):
        self.toucan.is_special = MagicMock(return_value=True)
        expected = {'/test/key': 'test_value'}
        json_data = [{
            'status': 'OK',
            'key': '/test/key',
            'value': 'test_value'
        }]

        mock_put.return_value = Response()
        mock_put.return_value.status_code = 200
        mock_put.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.put("test.keys", json_data)

        self.assertEqual(result, expected)
        mock_put.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/test/keys',
                                         json=json_data)

    @patch('utils.toucan.requests.get')
    def test_get_special_key_data_non_strict(self, mock_get):
        self.toucan.is_special = MagicMock(return_value=True)
        expected = {'test.key': 'some_value', 'other.key': 'other_value'}
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': {
                '/aucote/test/key': 'some_value',
                '/aucote/other/key': 'other_value'
            }
        }

        mock_get.return_value = Response()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.get("test.key", strict=False)

        self.assertCountEqual(result, expected)
        mock_get.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/test/key')

    def test_special_asterisk(self):
        self.assertTrue(self.toucan.is_special('test.endpoint.*'))

    def test_non_special(self):
        self.assertFalse(self.toucan.is_special('test.other.endpoint'))