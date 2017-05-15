from unittest import TestCase
from unittest.mock import patch, MagicMock

import requests

from fixtures.exploits import Exploit
from structs import Port, Node, Scan, TransportProtocol, Service, PhysicalPort
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

        self.node = Node(ip='127.0.0.1', node_id=None)

        self.port = Port(node=self.node, transport_protocol=TransportProtocol.TCP, number=22)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()
        self.port.service = Service()
        self.cpe_txt = 'cpe:/a:microsoft:internet_explorer:8.0.6001:beta'
        self.os_cpe_txt = 'cpe:/o:a:b:4'
        self.cpe_without_version = 'cpe:/o:cisco:ios'
        self.node.os.cpe = self.os_cpe_txt
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

    def test_call_with_port_without_cpe(self):
        self.port.service = Service()

        self.task.api_cvefor = MagicMock()
        self.task()

        self.assertFalse(self.task.api_cvefor.called)

    def test_call_with_cpe_without_version(self):
        self.port.service = Service()
        self.port.service.cpe = self.cpe_without_version

        self.task.api_cvefor = MagicMock()
        self.task()

        self.assertFalse(self.task.api_cvefor.called)

    def test_call_without_results(self):
        self.task.api_cvefor = MagicMock(return_value=[])
        self.task.store_vulnerability = MagicMock()
        self.task()

        self.assertFalse(self.task.store_vulnerability.called)

    @patch('tools.cve_search.tasks.Vulnerability')
    @patch('tools.cve_search.tasks.CVESearchVulnerabilityResults.from_dict')
    def test_call(self, mock_results, mock_vuln):
        self.task.api_cvefor = MagicMock()
        self.task.get_vulnerabilities = MagicMock()
        self.task.store_vulnerability = MagicMock()

        self.task()

        mock_results.assert_called_once_with(self.task.api_cvefor.return_value)
        self.task.store_vulnerability.assert_called_once_with(mock_vuln.return_value)
        mock_vuln.assert_called_once_with(exploit=self.task.exploit, port=self.task.port,
                                          output=mock_results.return_value.output)

    def test_get_node_cpe(self):
        self.task._port = PhysicalPort(node=self.node)
        cpe = self.task.get_cpe()
        self.assertEqual(cpe, self.node.os.cpe)
