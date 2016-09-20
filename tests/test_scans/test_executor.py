import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from scans import Executor
from structs import Node, Port, TransportProtocol
from utils.exceptions import TopdisConnectionException


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
    @patch('scans.executor.Executor._get_nodes_for_scanning', MagicMock(return_value=False))
    def setUp(self):
        self.executor = Executor(kudu_queue=MagicMock(), exploits=MagicMock(), storage=MagicMock())
        self.urllib_response = MagicMock()
        self.urllib_response.read = MagicMock()
        self.urllib_response.read.return_value = self.TODIS_RESPONSE
        self.urllib_response.headers.get_content_charset = MagicMock(return_value='utf-8')

    @patch('scans.executor.Executor._get_nodes')
    def test_init(self, mock_get_nodes):
        return_value = 'Test'
        mock_get_nodes.return_value=return_value
        executor = Executor(kudu_queue=MagicMock(), exploits=MagicMock(), storage=MagicMock())

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

    @patch('urllib.request.urlopen')
    @patch('urllib.error.URLError.__init__', MagicMock(return_value=None))
    def test_getting_nodes_cannot_connect_to_topdis(self, urllib):
        urllib.side_effect = URLError

        self.assertRaises(TopdisConnectionException, Executor._get_nodes)

    @patch('urllib.request.urlopen')
    def test_getting_nodes_unknown_exception(self, urllib):
        urllib.side_effect = Exception

        self.assertRaises(Exception, Executor._get_nodes)

    @patch('tools.masscan.MasscanPorts.scan_ports', MagicMock(return_value=[MagicMock()]))
    @patch('scans.executor.parse_period', MagicMock(return_value=10))
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

    def test_get_nodes_for_scanning(self):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1, name='test')
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2, name='test_2')
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3, name='test_3')

        nodes = [node_1, node_2,]

        self.executor._get_nodes = MagicMock(return_value=nodes)

        self.executor.storage.get_nodes = MagicMock(return_value=[node_2, node_3])

        result = self.executor._get_nodes_for_scanning()
        expected = [node_1]

        self.assertListEqual(result, expected)

    def test_get_ports_for_scanning(self):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1, name='test')
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2, name='test_2')
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3, name='test_3')

        port_1 = Port(node=node_1, number=80, transport_protocol=TransportProtocol.TCP)
        port_2 = Port(node=node_2, number=80, transport_protocol=TransportProtocol.TCP)
        port_3 = Port(node=node_3, number=80, transport_protocol=TransportProtocol.TCP)

        ports = [port_1, port_2]

        result = self.executor._get_ports_for_scanning(ports, [port_2, port_3])
        expected = [port_1]

        self.assertListEqual(result, expected)
