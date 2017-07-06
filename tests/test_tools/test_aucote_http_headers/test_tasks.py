from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.httpclient import HTTPClient, HTTPError, HTTPResponse, HTTPRequest
from tornado.testing import gen_test, AsyncTestCase

from structs import Port, Scan
from tools.aucote_http_headers.structs import HeaderDefinition, AucoteHttpHeaderResult
from tools.aucote_http_headers.tasks import AucoteHttpHeadersTask


class AucoteHttpHeadersTaskTest(AsyncTestCase):
    SERVER_RETURN = MagicMock(headers={
            'ETag': '"29cd-53f60a1426169-gzip"',
            'Vary': 'Accept-Encoding',
            'Accept-Ranges': 'bytes',
            'Content-Length': '3041',
            'Keep-Alive': 'timeout=5, max=100',
            'Server': 'Apache/2.4.23 (Debian)',
            'Content-Type': 'text/html',
            'Connection': 'Keep-Alive',
            'Last-Modified': 'Fri, 21 Oct 2016 14:12:18 GMT', 'Date': 'Thu, 27 Oct 2016 11:55:12 GMT',
            'X-Frame-Options': 'deny',
            'Access-Control-Allow-Origin': 'testowe',
            'Access-Control-Allow-Methods': 'testowe',
            'Access-Control-Allow-Headers': 'testowe',
            'Access-Control-Max-Age': 'testowe',
            'Content-Security-Policy': 'upgrade-insecure-requests;reflected-xss',
            'Content-Security-Policy-Report-Only': 'upgrade-insecure-requests; reflected-xss',
            'X-Content-Security-Policy': 'upgrade-insecure-requests; reflected-xss',
            'Upgrade-Insecure-Requests': '1',
            'Content-Encoding': 'testowe',
            'Public-Key-Pins (HPKP)': '',
            'Referrer-Policy': 'testowe',
            'Strict-Transport-Security (HSTS)': 'max-age=234',
            'X-Content-Type-Options': 'nosniff',
            'X-Download-Options': 'noopen',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'X-XSS-Protection': '1',})

    def setUp(self):
        super(AucoteHttpHeadersTaskTest, self).setUp()
        HTTPClient._instance = MagicMock()
        self.port = Port(node=MagicMock(), transport_protocol=None, number=None)
        self.port.scan = Scan()
        self.aucote = MagicMock()
        self.exploit = MagicMock()
        self.exploit.name = "test"
        self.config = {
            'headers': {
                'test': HeaderDefinition(pattern='test_nie', obligatory=True)
            }
        }
        self.custom_headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent': 'test'}
        self.task = AucoteHttpHeadersTask(port=self.port, aucote=self.aucote, exploits=[self.exploit],
                                          config=self.config)

    def tearDown(self):
        HTTPClient._instance = None

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(return_value='test'))
    @gen_test
    async def test_call(self, http_client):
        future = Future()
        future.set_result(self.SERVER_RETURN)
        http_client.instance().head.return_value = future

        self.exploit.name = 'test'
        self.task.current_exploits = [self.exploit]
        self.task.config = {
            'headers': {
                'test': HeaderDefinition(pattern='', obligatory=False)
            },
        }
        self.task.store_vulnerability = MagicMock()
        self.task.store_scan_end = MagicMock()
        self.assertEqual(await self.task(), [])
        http_client.instance().head.assert_called_once_with(url=self.port.url, headers=self.custom_headers,
                                                            validate_cert=False)

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(return_value='test'))
    @gen_test
    async def test_call_errors(self, http_client):

        exploit_1 = MagicMock()
        exploit_1.title = 'X-Frame-Options'
        exploit_1.name = 'exploit_1'
        exploit_2 = MagicMock()
        exploit_2.title = 'Access-Control-Non-Existing'
        exploit_2.name = 'exploit_2'
        exploit_3 = MagicMock()
        exploit_3.name = 'exploit_3'

        self.task.current_exploits = [exploit_1, exploit_2, exploit_3]

        self.task.config = {
            'headers': {
                'exploit_1': HeaderDefinition(pattern='^(SAMEORIGIN)$', obligatory=True),
                'exploit_2': HeaderDefinition(pattern='^((?!\*).)*$', obligatory=True),
                'exploit_3': HeaderDefinition(pattern='^((?!\*).)*$', obligatory=False)
            }
        }
        future = Future()
        future.set_result(self.SERVER_RETURN)
        http_client.instance().head.return_value = future
        self.task.store_vulnerability = MagicMock()
        self.task.store_scan_end = MagicMock()

        result = await self.task()
        expected = [
            AucoteHttpHeaderResult(output="Missing header: Access-Control-Non-Existing", exploit=exploit_2),
            AucoteHttpHeaderResult(output="Suspicious header value: X-Frame-Options: 'deny'", exploit=exploit_1),
        ]

        self.assertCountEqual(result, expected)

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(return_value='test'))
    @gen_test
    async def test_with_requests_connection_error(self, http_client):
        http_client.instance().head.side_effect = ConnectionError

        result = await self.task()
        expected = None

        self.assertEqual(result, expected)

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(return_value='test'))
    @gen_test
    async def test_with_requests_os_error(self, http_client):
        http_client.instance().head.side_effect = OSError

        result = await self.task()
        expected = None

        self.assertEqual(result, expected)

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.log')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(return_value='test'))
    @gen_test
    async def test_server_reponse_403_logging(self, mock_log, http_client):
        request = HTTPRequest(url='url')
        response = HTTPResponse(code=403, request=request)
        http_client.instance().head.side_effect = HTTPError(code=403, response=response)
        self.task.store_vulnerability = MagicMock()

        await self.task()

        self.assertTrue(mock_log.warning.called)

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.log')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(return_value='test'))
    @gen_test
    async def test_server_reponse_599(self, mock_log, http_client):
        http_client.instance().head.side_effect = HTTPError(code=403, response=None)
        self.task.store_vulnerability = MagicMock()

        result = await self.task()
        expected = None

        self.assertEqual(result, expected)

    @patch('tools.aucote_http_headers.tasks.HTTPClient')
    @patch('tools.aucote_http_headers.tasks.cfg.get', MagicMock(side_effect=(None, 'test')))
    @gen_test
    async def test_call_config_without_user_agent(self, http_client):
        future = Future()
        future.set_result(self.SERVER_RETURN)
        http_client.instance().head.return_value = future
        self.exploit.name = 'test'
        self.task.current_exploits = [self.exploit]
        self.task.config = {
            'headers': {
                'test': HeaderDefinition(pattern='', obligatory=False)
            },
        }
        self.task.store_vulnerability = MagicMock()
        self.task.store_scan_end = MagicMock()
        self.assertEqual(await self.task(), [])
        del self.custom_headers['User-Agent']
        http_client.instance().head.assert_called_once_with(url=self.port.url, headers=self.custom_headers,
                                                            validate_cert=False)
