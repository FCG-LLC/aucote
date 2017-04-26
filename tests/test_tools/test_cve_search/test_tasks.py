from unittest import TestCase
from unittest.mock import patch, MagicMock

import requests

from fixtures.exploits import Exploit
from structs import Port, Node, Scan, TransportProtocol, Service
from tools.cve_search.exceptions import CVESearchAPIException, CVESearchAPIConnectionException
from tools.cve_search.structs import CVESearchVulnerabilityResults, CVESearchVulnerabilityResult
from tools.cve_search.tasks import CVESearchServiceTask
from utils import Config


class CVESearchServiceTaskTest(TestCase):

    @patch('tools.cve_search.tasks.cfg', new_callable=Config)
    def setUp(self, cfg):
        cfg._cfg = {
            'tools': {
                'cve-search': {
                    'api': 'localhost:200'
                }
            }
        }

        self.port = Port(node=Node(ip='127.0.0.1', node_id=None), transport_protocol=TransportProtocol.TCP, number=22)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()
        self.port.service = Service()
        self.cpe_txt = 'cpe:/a:microsoft:internet_explorer:8.0.6001:beta'
        self.port.service.cpe = self.cpe_txt
        self.exploit = Exploit(exploit_id=1)
        self.aucote = MagicMock()
        self.task = CVESearchServiceTask(aucote=self.aucote, port=self.port, exploits=[self.exploit])

    def test_init(self):
        self.assertEqual(self.task.api, 'localhost:200')

    @patch('tools.cve_search.tasks.requests.get')
    def test_api_cvefor(self, mock_get):
        mock_get.return_value.status_code = 200

        service = Service()
        service.cpe = self.cpe_txt
        expected = mock_get.return_value.json.return_value
        result = self.task.api_cvefor(service.cpe)

        self.assertEqual(result, expected)
        mock_get.assert_called_once_with('localhost:200/cvefor/cpe:/a:microsoft:internet_explorer:8.0.6001:beta')

    @patch('tools.cve_search.tasks.requests.get')
    def test_api_cvefor_url_error(self, mock_get):
        mock_get.return_value.status_code = 404

        service = Service()
        service.cpe = self.cpe_txt
        self.assertRaises(CVESearchAPIException, self.task.api_cvefor, service.cpe)

    @patch('tools.cve_search.tasks.requests.get')
    def test_api_unavailable(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError
        service = Service()
        service.cpe = self.cpe_txt

        self.assertRaises(CVESearchAPIConnectionException, self.task.api_cvefor, service.cpe)

    def test_get_vulnerabilities(self):
        results = CVESearchVulnerabilityResults()

        vulnerability_1 = MagicMock()
        vulnerability_1.output = 'test_vuln'

        results.vulnerabilities.append(vulnerability_1)

        result = self.task.get_vulnerabilities(results=results)

        self.assertEqual(result[0].exploit, self.exploit)
        self.assertEqual(result[0].port, self.port)
        self.assertEqual(result[0].output, 'test_vuln')

    def test_call_with_port_without_cpe(self):
        self.port.service = Service()

        self.task.api_cvefor = MagicMock()
        self.task()

        self.assertFalse(self.task.api_cvefor.called)

    @patch('tools.cve_search.tasks.CVESearchVulnerabilityResults.from_dict')
    def test_call(self, mock_results):
        self.task.api_cvefor = MagicMock()
        self.task.get_vulnerabilities = MagicMock()
        self.task.store_vulnerabilities = MagicMock()

        self.task()

        mock_results.assert_called_once_with(self.task.api_cvefor.return_value)
        self.task.get_vulnerabilities.assert_called_once_with(mock_results.return_value)
        self.task.store_vulnerabilities.assert_called_once_with(self.task.get_vulnerabilities.return_value)
