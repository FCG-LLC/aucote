from unittest import TestCase
from unittest.mock import patch, MagicMock

import requests
from requests import Response

from utils import Config
from utils.exceptions import ToucanException
from utils.toucan import Toucan


class TestToucan(TestCase):

    def setUp(self):
        self.toucan = Toucan('toucan', '3000', 'http')

    @patch('utils.toucan.requests.get')
    def test_get_404(self, mock_get):
        mock_get.return_value = Response()
        mock_get.return_value.status_code = 404
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
        mock_put.assert_called_once_with(url='http://toucan:3000/config/aucote/test/key', json={'value': 'test_value'})

    @patch('utils.toucan.requests.put')
    def test_put_with_exception(self, mock_put):
        mock_put.side_effect = requests.exceptions.ConnectionError()

        self.assertRaises(ToucanException, self.toucan.put, "test.key", "test_value")
