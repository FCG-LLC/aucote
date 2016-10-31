from collections import KeysView
from unittest import TestCase
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from tools.aucote_http_headers.structs import HeaderDefinition
from tools.aucote_http_headers.tasks import AucoteHttpHeadersTask


class AucoteHttpHeadersTaskTest(TestCase):
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
        self.port = MagicMock(url='http://127.0.0.1:80/')
        self.executor = MagicMock()
        self.exploit = MagicMock()
        self.config = {
            'headers': {
                HeaderDefinition(name='Access-Control-Allow-Origin', pattern='test_nie', exploit=self.exploit)
            }
        }
        self.custom_headers = {'Accept-Encoding:': 'gzip, deflate'}
        self.task = AucoteHttpHeadersTask(port=self.port, executor=self.executor, exploit=self.exploit,
                                          config=self.config)

    @patch('tools.aucote_http_headers.tasks.requests')
    def test_call(self, mock_requests):
        mock_requests.head.return_value = self.SERVER_RETURN
        self.task.config = {
            'headers': set(),
        }
        self.task.store_vulnerability = MagicMock()
        self.task.store_scan_end = MagicMock()
        self.assertEqual(self.task(), [])
        mock_requests.head.assert_called_once_with(self.port.url, headers=self.custom_headers)

    @patch('tools.aucote_http_headers.tasks.requests')
    def test_call_errors(self, mock_requests):
        exploit_1 = MagicMock()
        exploit_1.title = 'X-Frame-Options'
        exploit_2 = MagicMock()
        exploit_2.title = 'Access-Control-Non-Existing'
        self.task.config['headers'] = {
            HeaderDefinition(name='X-Frame-Options', pattern='^(SAMEORIGIN)$', exploit=exploit_1),
            HeaderDefinition(name='Access-Control-Non-Existing', pattern='^((?!\*).)*$', exploit=exploit_2)
        }
        mock_requests.head.return_value = self.SERVER_RETURN
        self.task.store_vulnerability = MagicMock()
        self.task.store_scan_end = MagicMock()

        result = self.task()
        expected = [
            {
                "output": "Missing header: Access-Control-Non-Existing",
                "exploit": exploit_2,
            },
            {
                "output": "Suspicious header value: X-Frame-Options: 'deny'",
                "exploit": exploit_1,
            }
        ]

        self.assertCountEqual(result, expected)
