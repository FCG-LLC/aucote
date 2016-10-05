import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from scans.scan_task import ScanTask
from structs import Node
from utils.exceptions import TopdisConnectionException
from utils.storage import Storage


class ScanTaskTest(TestCase):
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

    @patch('scans.scan_task.ScanTask._get_nodes', MagicMock(return_value=[]))
    def setUp(self):
        self.urllib_response = MagicMock()
        self.urllib_response.read = MagicMock()
        self.urllib_response.read.return_value = self.TODIS_RESPONSE
        self.urllib_response.headers.get_content_charset = MagicMock(return_value='utf-8')
        self.scan_task = ScanTask(executor=MagicMock(storage=MagicMock()))

    @patch('scans.scan_task.http.urlopen')
    def test_getting_nodes(self, urllib):
        urllib.return_value = self.urllib_response

        nodes = ScanTask._get_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')

    @patch('scans.scan_task.http.urlopen')
    def test_getting_nodes_cannot_connect_to_topdis(self, urllib):
        urllib.side_effect = URLError('')

        self.assertRaises(TopdisConnectionException, ScanTask._get_nodes)

    @patch('scans.scan_task.http.urlopen')
    def test_getting_nodes_unknown_exception(self, urllib):
        urllib.side_effect = Exception

        self.assertRaises(Exception, ScanTask._get_nodes)

    @patch('scans.scan_task.ScanTask._get_nodes')
    @patch('scans.scan_task.cfg.get', MagicMock(return_value='5s'))
    @patch('scans.scan_task.parse_period', MagicMock(return_value=5))
    def test_get_nodes_for_scanning(self, mock_get_nodes):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)

        nodes = [node_1, node_2,]
        mock_get_nodes.return_value=nodes

        self.scan_task.storage = MagicMock()
        self.scan_task.storage.get_nodes = MagicMock(return_value=[node_2, node_3])

        result = self.scan_task._get_nodes_for_scanning()
        expected = [node_1]

        self.assertListEqual(result, expected)

    def test_call_magic(self):
        self.scan_task.scheduler = MagicMock()
        self.scan_task.run = MagicMock()

        self.scan_task()

        self.scan_task.run.assert_called_once_with()
        self.scan_task.scheduler.run.assert_called_once_with()

    @patch('scans.scan_task.MasscanPorts')
    @patch('scans.scan_task.Executor')
    def test_run(self, mock_executor, mock_masscan):
        self.scan_task.scheduler = MagicMock()
        self.scan_task.executor.add_task = MagicMock()
        self.scan_task._get_nodes_for_scanning = MagicMock()
        self.scan_task.storage = MagicMock()

        ports = [MagicMock()]
        mock_masscan.return_value.scan_ports.return_value = ports

        self.scan_task.run()

        self.scan_task.scheduler.enter.assert_called_once_with(self.scan_task.scan_period, 1, self.scan_task.run)
        mock_executor.called_once_with(aucote=self.scan_task.executor, nodes=ports)
        self.scan_task.executor.add_task.called_once_with(mock_executor.return_value)

    def test_run_without_nodes(self):
        self.scan_task._get_nodes_for_scanning = MagicMock(return_value=[])
        self.scan_task.run()
        self.assertFalse(self.scan_task.storage.save_nodes.called)