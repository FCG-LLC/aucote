from unittest.mock import MagicMock, patch

from tornado.testing import AsyncTestCase

from utils.http_client import HTTPClient


class HTTPClientTest(AsyncTestCase):
    def setUp(self):
        super(HTTPClientTest, self).setUp()
        self.client = HTTPClient()

    def test_init_instance(self):
        HTTPClient._instance = None
        client = HTTPClient.instance()
        self.assertEqual(HTTPClient._instance, client.instance())

    def test_existing_instance(self):
        old_instance = HTTPClient()
        HTTPClient._instance = old_instance
        new_instance = HTTPClient.instance()
        self.assertEqual(old_instance, new_instance)

    def tearDown(self):
        HTTPClient._instance = None

    @patch('utils.http_client.AsyncHTTPClient')
    @patch('utils.http_client.HTTPRequest')
    def test_request(self, request, mock_client):
        mock_client().fetch = MagicMock()
        self.client.request(method="TEST", a='1', b=5)
        request.assert_called_once_with(method="TEST", a='1', b=5)
        mock_client().fetch.assert_called_once_with(request(), self.client._handle_response)

    @patch('utils.http_client.AsyncHTTPClient')
    @patch('utils.http_client.HTTPRequest')
    def test_request_with_json(self, request, mock_client):
        mock_client().fetch = MagicMock()
        self.client.request(method="TEST", a='1', b=5, json={'test': 'test2'}, headers={'test': 'test_2'})
        request.assert_called_once_with(method="TEST", a='1', b=5, body='{"test":"test2"}',
                                        headers={'test': 'test_2', 'Content-Type': 'application/json'})
        mock_client().fetch.assert_called_once_with(request(), self.client._handle_response)

    def test_get(self):
        url = MagicMock()
        self.client.request = MagicMock()
        self.client.get(url, test='test')

        self.client.request.assert_called_once_with(url=url, test='test', method='GET')

    def test_head(self):
        url = MagicMock()
        self.client.request = MagicMock()
        self.client.head(url, test='test')

        self.client.request.assert_called_once_with(url=url, test='test', method='HEAD')

    def test_put(self):
        url = MagicMock()
        self.client.request = MagicMock()
        self.client.put(url, test='test')

        self.client.request.assert_called_once_with(url=url, test='test', method='PUT')

    @patch('utils.http_client.log')
    def test_handle_response_with_error(self, log):
        expected = MagicMock()
        result = self.client._handle_response(expected)
        self.assertTrue(log.info.called)
        self.assertEqual(result, expected)
