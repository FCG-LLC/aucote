from unittest import TestCase
from unittest.mock import patch, MagicMock

from scans import Executor


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class ExecutorTest(TestCase):
    TODIS_RESPONSE = b"""{
  "meta": {
    "apiVersion": "1.0.0",
    "requestTime": "2016-08-11T11:42:32.842891+00:00",
    "url": "http://10.12.1.175:1234/api/v1/nodes?ip=t"
  },
  "nodes": [
    {
      "deviceType": "Router",
      "displayName": "EPSON1B0407",
      "id": 573,
      "ips": [
        "10.3.3.99"
      ],
      "managementIp": "10.3.3.99",
      "snmp": {
        "communityString": "public",
        "port": 161,
        "version": "1"
      }
    },
    {
      "deviceType": "Unknown",
      "displayName": "10.12.2.57",
      "id": 1169,
      "ips": [
        "10.12.2.57"
      ],
      "managementIp": "10.12.2.57",
      "snmp": null
    },
    {
      "deviceType": "Host",
      "displayName": "10.3.3.60",
      "id": 15387,
      "ips": [
        "10.3.3.60"
      ],
      "managementIp": "10.3.3.60",
      "snmp": null
    },
    {
      "deviceType": "Router",
      "displayName": "csr1.fcg.com",
      "id": 259,
      "ips": [
        "172.19.19.2",
        "10.90.90.1",
        "10.1.10.1",
        "10.12.10.1",
        "10.12.2.4",
        "10.12.2.1"
      ],
      "managementIp": "10.12.2.1",
      "snmp": {
        "communityString": "fishman",
        "port": 161,
        "version": "2c"
      }
    }
  ]
}"""

    @patch('scans.executor.Executor._get_nodes', MagicMock(return_value=False))
    def setUp(self):
        self.executor = Executor(kudu_queue=MagicMock())
        self.urllib_response = MagicMock()
        self.urllib_response.read = MagicMock()
        self.urllib_response.read.return_value = self.TODIS_RESPONSE

        self.urllib_response.headers.get_content_charset = MagicMock(return_value='utf-8')

    @patch('scans.executor.Executor._get_nodes')
    def test_init(self, mock_get_nodes):
        return_value = 'Test'
        mock_get_nodes.return_value=return_value
        executor = Executor(kudu_queue=MagicMock())
        mock_get_nodes.assert_called_once_with()

        self.assertEqual(executor.nodes, return_value)

    @patch('urllib.request.urlopen')
    def test_getting_nodes(self, urllib):
        urllib.return_value = self.urllib_response

        nodes = Executor._get_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')

    @patch('tools.masscan.MasscanPorts.scan_ports', MagicMock(return_value=[MagicMock()]))
    @patch('utils.threads.ThreadPool.stop')
    @patch('utils.threads.ThreadPool.join')
    @patch('utils.threads.ThreadPool.start')
    def test_run_executor(self, mock_start, mock_join, mock_stop):
        mock_thread_pool = MagicMock(return_value=None)
        thread_pool = MagicMock()
        mock_thread_pool.return_value = thread_pool

        self.executor._get_nodes = MagicMock()
        self.executor.run()
        self.assertEqual(mock_start.call_count, 1)
        self.assertEqual(mock_join.call_count, 1)
        self.assertEqual(mock_stop.call_count,1)

    def test_properties(self):
        self.assertEqual(self.executor.exploits, self.executor._exploits)
        self.assertEqual(self.executor.kudu_queue, self.executor._kudu_queue)

