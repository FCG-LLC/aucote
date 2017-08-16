from unittest.mock import patch, MagicMock

from cpe import CPE
from tornado.concurrent import Future
from tornado.httpclient import HTTPError, HTTPRequest, HTTPResponse
from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from structs import Port, Node, Scan, TransportProtocol, Service, PhysicalPort
from tools.cve_search.exceptions import CVESearchApiException
from tools.cve_search.structs import CVESearchVulnerabilityResults
from tools.cve_search.tasks import CVESearchServiceTask
from utils import Config

future = Future()
future.set_result(True)


@patch('utils.http_client.gen.sleep', MagicMock(return_value=future))
class CVESearchServiceTaskTest(AsyncTestCase):

    @patch('tools.cve_search.tasks.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(CVESearchServiceTaskTest, self).setUp()
        cfg._cfg = {
            'tools': {
                'cve-search': {
                    'api': 'localhost:200'
                }
            }
        }

        self.node = Node(ip='127.0.0.1', node_id=None)

        self.port = Port(node=self.node, transport_protocol=TransportProtocol.TCP, number=22)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()
        self.port.service = Service()
        self.app = Service()
        self.app_2 = Service()
        self.app.cpe = 'cpe:/a:microsoft:iexplorer:8.0.6001:beta'
        self.app_2.cpe = 'cpe:/a:microsoft:aexplorer:8.0.6001:beta'
        self.cpe_txt = 'cpe:/a:microsoft:internet_explorer:8.0.6001:beta'
        self.os_cpe_txt = 'cpe:/o:a:b:4'
        self.cpe_without_version = 'cpe:/o:cisco:ios'
        self.node.os.cpe = self.os_cpe_txt
        self.port.service.cpe = self.cpe_txt
        self.exploit = Exploit(exploit_id=1)
        self.aucote = MagicMock()
        self.scan = Scan()
        self.task = CVESearchServiceTask(aucote=self.aucote, port=self.port, exploits=[self.exploit], scan=self.scan)

    def test_init(self):
        self.assertEqual(self.task.api, 'localhost:200')

    @patch('tools.cve_search.tasks.HTTPClient')
    @gen_test
    async def test_api_cvefor(self, mock_http,):
        json_data = '{"test_key": "test_value"}'
        response = HTTPResponse(code=200, buffer='', request=HTTPRequest('test_url'))
        mock_get = mock_http.instance.return_value.get
        mock_get.return_value = Future()
        mock_get.return_value.set_result(response)
        response._body = json_data.encode()

        service = Service()
        service.cpe = self.cpe_txt
        expected = {'test_key': 'test_value'}
        result = await self.task.api_cvefor(service.cpe)

        self.assertEqual(result, expected)
        mock_get.assert_called_once_with('localhost:200/cvefor/cpe%3A2.3%3Aa%3Amicrosoft%3Ainternet_explorer%3A8.0.6001%3Abeta%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A',)

    @patch('tools.cve_search.tasks.HTTPClient')
    @gen_test
    async def test_api_cvefor_http_error(self, mock_http):
        mock_http.instance().get.side_effect = HTTPError(code=404)

        service = Service()
        service.cpe = self.cpe_txt
        with self.assertRaises(CVESearchApiException):
            await self.task.api_cvefor(service.cpe)

    @patch('tools.cve_search.tasks.HTTPClient')
    @gen_test
    async def test_api_unavailable(self, mock_http):
        mock_http.instance().get.side_effect = ConnectionError()

        service = Service()
        service.cpe = self.cpe_txt
        with self.assertRaises(CVESearchApiException):
            await self.task.api_cvefor(service.cpe)

    def test_get_vulnerabilities(self):
        results = CVESearchVulnerabilityResults()

        vulnerability_1 = MagicMock()
        vulnerability_1.output = 'test_vuln'

        results.vulnerabilities = (vulnerability_1, )

        result = self.task.get_vulnerabilities(results=results)

        self.assertEqual(result[0].exploit, self.exploit)
        self.assertEqual(result[0].port, self.port)
        self.assertEqual(result[0].output, 'test_vuln')

    @gen_test
    async def test_call_with_port_without_cpe(self):
        self.port.service = Service()

        self.task.api_cvefor = MagicMock(return_value=Future())
        self.task.api_cvefor.return_value.set_result(True)

        await self.task()

        self.assertFalse(self.task.api_cvefor.called)

    @gen_test
    async def test_call_with_cpe_without_version(self):
        self.port.service = Service()
        self.port.service.cpe = self.cpe_without_version

        self.task.api_cvefor = MagicMock()
        await self.task()

        self.assertFalse(self.task.api_cvefor.called)

    @gen_test
    async def test_call_without_results(self):
        self.task.api_cvefor = MagicMock(return_value=Future())
        self.task.api_cvefor.return_value.set_result([])
        self.task.store_vulnerability = MagicMock()
        await self.task()

        self.assertFalse(self.task.store_vulnerability.called)

    @patch('tools.cve_search.tasks.Vulnerability')
    @patch('tools.cve_search.tasks.CVESearchParser.dict_to_results')
    @gen_test
    async def test_call(self, mock_results, mock_vuln):
        expected = MagicMock()
        self.task.api_cvefor = MagicMock(return_value=Future())
        self.task.api_cvefor.return_value.set_result([expected])
        self.task.get_vulnerabilities = MagicMock()
        self.task.store_vulnerability = MagicMock()

        await self.task()

        mock_results.assert_called_once_with([expected])
        self.task.store_vulnerability.assert_called_once_with(mock_vuln.return_value)
        mock_vuln.assert_called_once_with(exploit=self.task.exploit, port=self.task.port,
                                          output=mock_results.return_value.output)

    def test_get_node_cpe(self):
        self.task._port = PhysicalPort(node=self.node)
        cpe = self.task.get_cpes()
        self.assertEqual(cpe, [self.node.os.cpe])

    def test_get_apache_httpd_cpe(self):
        self.task._port.service.cpe = 'cpe:2.3:a:apache:httpd:2.4.18:*:*:*:*:*:*:*'
        expected = [CPE('cpe:2.3:a:apache:httpd:2.4.18:*:*:*:*:*:*:*'),
                    CPE('cpe:2.3:a:apache:http_server:2.4.18:*:*:*:*:*:*:*')]
        result = self.task.get_cpes()
        self.assertEqual(result, expected)

    def test_get_apache_http_server_cpe(self):
        self.task._port.service.cpe = 'cpe:2.3:a:apache:http_server:2.4.18:*:*:*:*:*:*:*'
        expected = [CPE('cpe:2.3:a:apache:http_server:2.4.18:*:*:*:*:*:*:*'),
                    CPE('cpe:2.3:a:apache:httpd:2.4.18:*:*:*:*:*:*:*')]
        result = self.task.get_cpes()
        self.assertEqual(result, expected)

    @patch('tools.cve_search.tasks.HTTPClient')
    @gen_test
    async def test_get_cisco_with_brackets(self, mock_http):
        self.task.api = ''
        json_data = '{"test_key": "test_value"}'
        response = HTTPResponse(code=200, buffer='', request=HTTPRequest('test_url'))
        mock_get = mock_http.instance.return_value.get
        mock_get.return_value = Future()
        mock_get.return_value.set_result(response)
        response._body = json_data.encode()

        cpe = CPE('cpe:2.3:o:cisco:ios:12.2\(52\)se:*:*:*:*:*:*:*')
        expected = '/cvefor/cpe%3A2.3%3Ao%3Acisco%3Aios%3A12.2%25252852%252529se%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A'

        await self.task.api_cvefor(cpe)

        mock_get.assert_called_once_with(expected)

    def test_unique_cpe(self):
        cpe_1 = CPE('cpe:2.3:o:cisco:ios:12.2\(52\)se:*:*:*:*:*:*:*')
        cpe_2 = CPE('cpe:2.3:o:cisco:ios:12.2\(52\)se:*:*:*:*:*:*:*')
        expected = [cpe_1]

        result = self.task._unique_cpes([cpe_1, cpe_2])

        self.assertCountEqual(result, expected)

    @patch('tools.cve_search.tasks.Vulnerability')
    @patch('tools.cve_search.tasks.CVESearchParser.dict_to_results')
    @gen_test
    async def test_call_with_api_exception(self, mock_results, mock_vuln):
        expected = MagicMock()
        future = Future()
        future.set_result([expected])
        self.port.apps = [self.app, self.app_2]
        self.task.api_cvefor = MagicMock(side_effect=(CVESearchApiException('just test'), future))
        self.task.get_vulnerabilities = MagicMock()
        self.task.store_vulnerability = MagicMock()

        await self.task()

        mock_results.assert_called_once_with([expected])
        self.task.store_vulnerability.assert_called_once_with(mock_vuln.return_value)
        mock_vuln.assert_called_once_with(exploit=self.task.exploit, port=self.task.port,
                                          output=mock_results.return_value.output)
