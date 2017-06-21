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

    @patch('utils.http_client.HTTPRequest')
    def test_request(self, request):
        self.client._client.fetch = MagicMock()
        self.client.request(method="TEST", a='1', b=5)
        request.assert_called_once_with(method="TEST", a='1', b=5)
        self.client._client.fetch.assert_called_once_with(request(), self.client._handle_response)

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

    @patch('utils.http_client.log')
    def test_handle_response_with_error(self, log):
        expected = MagicMock()
        result = self.client._handle_response(expected)
        self.assertTrue(log.error.called)
        self.assertEqual(result, expected)
