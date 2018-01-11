from unittest.mock import MagicMock, patch

from cpe import CPE
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from structs import CPEType
from utils import Config
from utils.topdis import Topdis


class TopdisTest(AsyncTestCase):
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

    NODE_DETAILS = rb"""{
          "meta": {
            "apiVersion": "1.0.0",
            "requestTime": "2017-05-08T12:50:20.139895+00:00",
            "url": "http://dev03.cs.int:1234/api/v1/node?id=24"
          },
          "nodes": [
            {
              "description": "Cisco IOS Software, C181X Software (C181X-ADVIPSERVICESK9-M), Version 12.4(11)XW, RELEASE SOFTWARE (fc1)\r\nSynched to technology version 12.4(12.12)T\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2007 by Cisco Systems, Inc.\r\nComp",
              "deviceType": "L3 Switch",
              "deviceTypeDiscoveryType": "DIRECT",
              "displayName": "fishconnectVPN.fcg.com",
              "hardware": {
                "model": "CISCO1811W-AG-B/K9",
                "sysObjId": "1.3.6.1.4.1.9.1.641",
                "vendor": "ciscoSystems"
              },
              "id": 24,
              "isCloud": false,
              "isHost": false,
              "managementIp": "10.80.80.2",
              "name": "fishconnectVPN.fcg.com",
              "serialNumber": "FHK113515FT",
              "snmp": {
                "communityString": "public",
                "port": 161,
                "version": "2c"
              },
              "software": {
                "os": "IOS",
                "osDiscoveryType": "DIRECT",
                "osVersion": "12.4(11)XW, RELEASE SOFTWARE (fc1)"
              },
              "stateId": 6597,
              "supportsNat": false
            }
          ]
        }"""

    NODE_WITH_OS_FINGERPRINT = rb"""{
      "meta": {
        "apiVersion": "1.0.0",
        "requestTime": "2016-08-11T11:42:32.842891+00:00",
        "url": "http://10.12.1.175:1234/api/v1/nodes?ip=t"
      },
      "nodes": [
        {
          "id": 573,
          "displayName": "EPSON1B0407",
          "ips": [
            "10.3.3.99"
          ],
          "software": {
            "os": {
                "discoveryType": "FINGERPRINT"
            }
          }
        }
      ]
    }"""

    NODE_WITH_OS_DIRECT = rb"""{
      "meta": {
        "apiVersion": "1.0.0",
        "requestTime": "2016-08-11T11:42:32.842891+00:00",
        "url": "http://10.12.1.175:1234/api/v1/nodes?ip=t"
      },
      "nodes": [
        {
          "id": 573,
          "displayName": "EPSON1B0407",
          "ips": [
            "10.3.3.99"
          ],
          "software": {
            "os": {
                "discoveryType": "DIRECT",
                "name": "test_name",
                "version": "11"
            }
          }
        }
      ]
    }"""

    NODE_WITH_OS_DIRECT_SPACES_VERSION = rb"""{
      "meta": {
        "apiVersion": "1.0.0",
        "requestTime": "2016-08-11T11:42:32.842891+00:00",
        "url": "http://10.12.1.175:1234/api/v1/nodes?ip=t"
      },
      "nodes": [
        {
          "id": 573,
          "displayName": "EPSON1B0407",
          "ips": [
            "10.3.3.99"
          ],
          "software": {
            "os": {
                "discoveryType": "DIRECT",
                "name": "test_name",
                "version": "11 abcde"
            }
          }
        }
      ]
    }"""

    EMPTY_NODE_DETAILS = rb"""{
      "meta": {
        "apiVersion": "1.0.0",
        "requestTime": "2017-05-08T12:50:20.139895+00:00",
        "url": "http://dev03.cs.int:1234/api/v1/node?id=24"
      },
      "nodes": [
      ]
    }"""

    def setUp(self):
        super(TopdisTest, self).setUp()
        self.topdis = Topdis('localhost', 1234, '/api/v1')
        self.req_future = Future()
        self.http_client_response = MagicMock()
        self.http_client_response.body = self.TODIS_RESPONSE
        self.cfg = {

        }

    @patch('utils.topdis.HTTPClient')
    @gen_test
    async def test_getting_nodes_os_fingerprint(self, http_client):
        self.req_future.set_result(MagicMock(body=self.NODE_WITH_OS_FINGERPRINT))
        http_client.instance().get.return_value = self.req_future

        nodes = await self.topdis.get_nodes()
        self.assertEqual(len(nodes), 1)
        result = nodes[0]

        self.assertIsNone(result.os.name)
        self.assertIsNone(result.os.version)

    @patch('utils.topdis.HTTPClient')
    @gen_test
    async def test_getting_nodes(self, http_client):
        self.req_future.set_result(self.http_client_response)
        http_client.instance().get.return_value = self.req_future

        nodes = await self.topdis.get_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')

    @patch('utils.topdis.HTTPClient')
    @patch('utils.topdis.Service.build_cpe')
    @gen_test
    async def test_getting_nodes_os_direct(self, mock_cpe, http_client):
        self.req_future.set_result(MagicMock(body=self.NODE_WITH_OS_DIRECT))
        http_client.instance().get.return_value = self.req_future
        mock_cpe.return_value = 'cpe:2.3:a:b:c:d:*:*:*:*:*:*:*'

        nodes = await self.topdis.get_nodes()
        self.assertEqual(len(nodes), 1)
        result = nodes[0]

        self.assertEqual(result.os.name, 'test_name')
        self.assertEqual(result.os.version, '11')
        self.assertEqual(result.os.cpe, CPE(mock_cpe.return_value))
        mock_cpe.assert_called_once_with(product='test_name', version='11', part=CPEType.OS)

    @patch('utils.topdis.HTTPClient')
    @patch('utils.topdis.Service.build_cpe')
    @gen_test
    async def test_getting_nodes_os_direct_with_space_in_version(self, mock_cpe, http_client):
        self.req_future.set_result(MagicMock(body=self.NODE_WITH_OS_DIRECT_SPACES_VERSION))
        http_client.instance().get.return_value = self.req_future
        mock_cpe.side_effect = KeyError()

        nodes = await self.topdis.get_nodes()
        self.assertEqual(len(nodes), 1)
        result = nodes[0]

        self.assertEqual(result.os.name, 'test_name')
        self.assertEqual(result.os.version, '11 abcde')
        self.assertIsNone(result.os.cpe)

    @patch('utils.topdis.HTTPClient')
    @gen_test
    async def test_scan_time_init(self, http_client):
        self.req_future.set_result(self.http_client_response)
        http_client.instance().get.return_value = self.req_future

        result = await self.topdis.get_nodes()
        expected = 1470915752.842891

        self.assertEqual(result[0].scan.start, expected)

        @patch('utils.topdis.HTTPClient')
        @gen_test
        async def test_getting_nodes_unknown_exception(self, http_client):
            http_client.instance().get.side_effect = Exception
            with self.assertRaises(Exception):
                await self.topdis.get_nodes()