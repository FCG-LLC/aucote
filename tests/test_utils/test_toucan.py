from unittest import TestCase
from unittest.mock import patch, MagicMock, call

import requests
from requests import Response

from utils import Config
from utils.exceptions import ToucanException, ToucanUnsetException
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
    def test_get_with_exception(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError()

        self.assertRaises(ToucanException, self.toucan.get, "test.key")

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
        expected = [('test.key', 'test_value')]
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
    def test_put_with_exception(self, mock_put):
        mock_put.side_effect = requests.exceptions.ConnectionError()

        self.assertRaises(ToucanException, self.toucan.put, "test.key", "test_value")

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

    @patch('utils.toucan.requests.put')
    def test_put_special_key_data(self, mock_put):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/key': 'new_endpoint'
        }
        expected = 'test_value'
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': expected
        }

        self.toucan.get = MagicMock(return_value={
            '/aucote/test/key': 'some_value',
            '/aucote/other/key': 'other_value'
        })

        mock_put.return_value = Response()
        mock_put.return_value.status_code = 200
        mock_put.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.put("test.key", "new_value")

        self.assertEqual(result, expected)
        mock_put.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/new_endpoint',
                                         json={'value': {
                                             '/aucote/test/key': 'new_value',
                                             '/aucote/other/key': 'other_value'
                                         }})

    @patch('utils.toucan.requests.put')
    def test_put_special_key_data_for_unset_endpoint(self, mock_put):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/key': 'new_endpoint'
        }
        expected = 'test_value'
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': expected
        }

        self.toucan.get = MagicMock(side_effect=ToucanUnsetException)

        mock_put.return_value = Response()
        mock_put.return_value.status_code = 200
        mock_put.return_value.json = MagicMock(return_value=json_data)

        result = self.toucan.put("test.key", "new_value")

        self.assertEqual(result, expected)
        mock_put.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/new_endpoint',
                                         json={'value': {'/aucote/test/key': 'new_value'}})

    @patch('utils.toucan.requests.get')
    def test_get_special_key_data_non_strict(self, mock_get):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/key': 'new_endpoint'
        }
        expected = [('test.key', 'some_value'), ('other.key', 'other_value')]
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
        mock_get.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/new_endpoint')

    @patch('utils.toucan.requests.get')
    def test_get_special_key_data_strict(self, mock_get):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/key': 'new_endpoint'
        }
        expected = 'some_value'
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

        result = self.toucan.get("test.key", strict=True)

        self.assertEqual(result, expected)
        mock_get.assert_called_once_with(url='test_prot://test_host:3000/config/aucote/new_endpoint')

    @patch('utils.toucan.requests.get')
    def test_get_special_key_data_strict_exception(self, mock_get):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/key': 'new_endpoint'
        }
        expected = 'some_value'
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': {
                '/aucote/other/key': 'other_value'
            }
        }

        mock_get.return_value = Response()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = MagicMock(return_value=json_data)

        self.assertRaises(ToucanUnsetException, self.toucan.get, "test.key", strict=True)

    def test_special(self):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/endpoint': 'other_endpoint'
        }

        self.assertTrue(self.toucan.is_special('test.endpoint'))

    def test_special_asterisk(self):
        self.assertTrue(self.toucan.is_special('test.endpoint.*'))

    def test_non_special(self):
        self.toucan.SPECIAL_ENDPOINTS = {
            'test/endpoint': 'other_endpoint'
        }

        self.assertFalse(self.toucan.is_special('test.other.endpoint'))