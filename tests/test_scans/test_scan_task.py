from unittest import TestCase
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from scans.scan_task import ScanTask
from utils.exceptions import TopdisConnectionException


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

    def setUp(self):
        self.urllib_response = MagicMock()
        self.urllib_response.read = MagicMock()
        self.urllib_response.read.return_value = self.TODIS_RESPONSE
        self.urllib_response.headers.get_content_charset = MagicMock(return_value='utf-8')

    @patch('urllib.request.urlopen')
    def test_getting_nodes(self, urllib):
        urllib.return_value = self.urllib_response

        nodes = ScanTask._get_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')


    @patch('urllib.request.urlopen')
    @patch('urllib.error.URLError.__init__', MagicMock(return_value=None))
    def test_getting_nodes_cannot_connect_to_topdis(self, urllib):
        urllib.side_effect = URLError

        self.assertRaises(TopdisConnectionException, ScanTask._get_nodes)


    @patch('urllib.request.urlopen')
    def test_getting_nodes_unknown_exception(self, urllib):
        urllib.side_effect = Exception

        self.assertRaises(Exception, ScanTask._get_nodes)