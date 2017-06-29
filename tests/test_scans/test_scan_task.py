import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call

import time

from cpe import CPE
from croniter import croniter
from netaddr import IPSet
from tornado.concurrent import Future
from tornado.httpclient import HTTPError
from tornado.testing import AsyncTestCase, gen_test

from scans.scan_task import ScanTask
from structs import Node, CPEType, TransportProtocol, Port, PhysicalPort
from utils import Config
from utils.async_task_manager import AsyncTaskManager


class ScanTaskTest(AsyncTestCase):
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

    NODE_DETAILS_FOR_CPE = rb"""{
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
            "osVersion": "12.4(11)XW"
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

    @patch('scans.scan_task.ScanTask._get_topdis_nodes', MagicMock(return_value=[]))
    @patch('scans.scan_task.croniter', MagicMock(return_value=croniter('* * * * *', time.time())))
    @patch('scans.scan_task.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(ScanTaskTest, self).setUp()
        self.cfg = {
            'portdetection': {
                'test_name':{
                    'scan_type': 'LIVE',
                    'live_scan': {
                        'min_time_gap': 0,
                    },
                    'periodic_scan': {
                        'cron': '* * * * *'
                    },
                    'ports': {
                        'tcp': {
                            'include': [],
                            'exclude': []
                        },
                        'udp': {
                            'include': [],
                            'exclude': []
                        },
                        'sctp': {
                            'include': [],
                            'exclude': []
                        },
                    }
                },
                '_internal': {
                    'tools_cron': '* * * * *',
                    'nmap_udp': False
                }
            },
            'topdis': {
                'api': {
                    'host': '',
                    'port': ''
                },
            }
        }

        cfg._cfg = self.cfg
        self.http_client_response = MagicMock()
        self.http_client_response.body = self.TODIS_RESPONSE
        self.req_future = Future()
        self.aucote = MagicMock(storage=MagicMock())
        atm_stop_future = Future()
        self.atm_stop = MagicMock()
        atm_stop_future.set_result(self.atm_stop)
        self.aucote.async_task_manager.stop.return_value = atm_stop_future

        self.task = ScanTask(aucote=self.aucote)
        self.task._cron_tasks = {
            1: MagicMock(),
            2: MagicMock()
        }
        self.task_manager = AsyncTaskManager.instance()
        self.task_manager.run_tasks = {
            '_run_tools': False,
            '_scan': False
        }
        self.task.NAME = 'test_name'

    def tearDown(self):
        AsyncTaskManager.instance().clear()

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @gen_test
    async def test_getting_nodes(self, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(self.http_client_response)
        http_client.instance().get.return_value = self.req_future

        nodes = await self.task._get_topdis_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @gen_test
    async def test_getting_nodes_os_fingerprint(self, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(MagicMock(body=self.NODE_WITH_OS_FINGERPRINT))
        http_client.instance().get.return_value = self.req_future

        nodes = await self.task._get_topdis_nodes()
        self.assertEqual(len(nodes), 1)
        result = nodes[0]

        self.assertIsNone(result.os.name)
        self.assertIsNone(result.os.version)

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.Service.build_cpe')
    @gen_test
    async def test_getting_nodes_os_direct(self, mock_cpe, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(MagicMock(body=self.NODE_WITH_OS_DIRECT))
        http_client.instance().get.return_value = self.req_future
        mock_cpe.return_value = 'cpe:2.3:a:b:c:d:*:*:*:*:*:*:*'

        nodes = await self.task._get_topdis_nodes()
        self.assertEqual(len(nodes), 1)
        result = nodes[0]

        self.assertEqual(result.os.name, 'test_name')
        self.assertEqual(result.os.version, '11')
        self.assertEqual(result.os.cpe, CPE(mock_cpe.return_value))
        mock_cpe.assert_called_once_with(product='test_name', version='11', type=CPEType.OS)

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.Service.build_cpe')
    @gen_test
    async def test_getting_nodes_os_direct_with_space_in_version(self, mock_cpe, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(MagicMock(body=self.NODE_WITH_OS_DIRECT_SPACES_VERSION))
        http_client.instance().get.return_value = self.req_future
        mock_cpe.return_value = 'cpe:2.3:a:b:c:d:*:*:*:*:*:*:*'

        nodes = await self.task._get_topdis_nodes()
        self.assertEqual(len(nodes), 1)
        result = nodes[0]

        self.assertEqual(result.os.name, 'test_name')
        self.assertEqual(result.os.version, '11 abcde')
        self.assertIsNone(result.os.cpe)
        self.assertFalse(mock_cpe.called)

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @gen_test
    async def test_getting_nodes_cannot_connect_to_topdis(self, cfg, http_client):
        cfg._cfg = self.cfg
        http_client.instance().get.side_effect = HTTPError('')
        result = await self.task._get_topdis_nodes()
        expected = []

        self.assertEqual(result, expected)

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @gen_test
    async def test_getting_nodes_connection_error_to_topdis(self, cfg, http_client):
        cfg._cfg = self.cfg
        http_client.instance().get.side_effect = ConnectionError('')
        result = await self.task._get_topdis_nodes()
        expected = []

        self.assertEqual(result, expected)

    @patch('scans.scan_task.HTTPClient')
    @gen_test
    async def test_getting_nodes_unknown_exception(self, http_client):
        http_client.instance().get.side_effect = Exception
        with self.assertRaises(Exception):
            await self.task._get_topdis_nodes()

    @patch('scans.scan_task.ScanTask._get_topdis_nodes')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.parse_period', MagicMock(return_value=5))
    @gen_test
    async def test_get_nodes_for_scanning(self, cfg, mock_get_nodes):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.networks.include'] = ['127.0.0.2/31']

        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)

        nodes = [node_1, node_2, node_3]
        mock_get_nodes.return_value = Future()
        mock_get_nodes.return_value.set_result(nodes)

        self.task.storage.get_nodes = MagicMock(return_value=[node_2])

        result = await self.task._get_nodes_for_scanning()
        expected = [node_3]

        self.assertListEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_get_networks_list(self, cfg):
        cfg['portdetection.test_name.networks.include'] = ['127.0.0.1/24', '128.0.0.1/13']
        result = self.task._get_networks_list()
        expected = IPSet(['127.0.0.1/24', '128.0.0.1/13'])

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg.get', MagicMock(side_effect=KeyError("test")))
    def test_get_networks_list_no_cfg(self):
        self.assertRaises(SystemExit, self.task._get_networks_list)

    @patch('scans.scan_task.HTTPClient')
    @patch('scans.scan_task.cfg', new_callable=Config)
    @gen_test
    async def test_scan_time_init(self, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(self.http_client_response)
        http_client.instance().get.return_value = self.req_future

        result = await self.task._get_topdis_nodes()
        expected = 1470915752.842891

        self.assertEqual(result[0].scan.start, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.time.time', MagicMock(return_value=595))
    def test_previous_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.scan_type'] = 'PERIODIC'
        cfg['portdetection.test_name.periodic_scan.cron'] = '* * * * *'

        expected = 480
        result = self.task.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.time.time', MagicMock(return_value=595))
    def test_previous_scan_second_test(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.scan_type'] = 'PERIODIC'
        cfg['portdetection.test_name.periodic_scan.cron'] = '*/12 * * * *'

        expected = 0
        result = self.task.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_task.ScanTask.previous_scan', new_callable=PropertyMock)
    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_get_ports_for_scan(self, cfg, mock_previous):
        cfg._cfg = self.cfg
        nodes = [MagicMock(), MagicMock(), MagicMock()]
        mock_previous.return_value = 100
        ports = [
            MagicMock(),
            MagicMock(),
            MagicMock()
        ]
        self.task.storage.get_ports_by_nodes.return_value = ports

        result = self.task.get_ports_for_scan(nodes)

        self.assertEqual(result, ports)
        self.task.storage.get_ports_by_nodes.assert_has_calls([call(nodes=nodes, timestamp=100)])

    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.time.time', MagicMock(return_value=595))
    def test_next_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.scan_type'] = 'PERIODIC'
        cfg['portdetection.test_name.cron'] = '*/5 * * * *'

        expected = 600
        result = self.task.next_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_scan_cron(self, cfg):
        expected = "* * * * */45"
        cfg['portdetection.test_name.scan_type'] = "PERIODIC"
        cfg['portdetection.test_name.periodic_scan.cron'] = expected
        result = self.task._scan_cron()
        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_scan_interval_periodic(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "PERIODIC"

        result = self.task._scan_interval()
        expected = 0

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_scan_interval_live(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "LIVE"
        cfg['portdetection.test_name.live_scan.min_time_gap'] = "5m13s"

        result = self.task._scan_interval()
        expected = 313

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_scan_cron_periodic(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "PERIODIC"
        cfg['portdetection.test_name.periodic_scan.cron'] = "*/2 3 */5 * *"

        result = self.task._scan_cron()
        expected = "*/2 3 */5 * *"

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_scan_cron_live(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "LIVE"

        result = self.task._scan_cron()
        expected = '* * * * *'

        self.assertEqual(result, expected)

    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_filter_out_ports(self, cfg):
        cfg['portdetection.tcp.ports.include'] = ['23-26']
        cfg['portdetection.tcp.ports.exclude'] = ['25']
        cfg['portdetection.udp.ports.include'] = ['25', '98']
        cfg['portdetection.udp.ports.exclude'] = ['25']
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        tcp_allow = Port(transport_protocol=TransportProtocol.TCP, number=26, node=node)
        tcp_deny = Port(transport_protocol=TransportProtocol.TCP, number=25, node=node)
        udp_allow = Port(transport_protocol=TransportProtocol.UDP, number=98, node=node)
        udp_deny = Port(transport_protocol=TransportProtocol.UDP, number=25, node=node)

        ports = [tcp_allow, tcp_deny, udp_allow, udp_deny]

        result = self.task._filter_out_ports(ports)
        expected = [tcp_allow, udp_allow]

        self.assertCountEqual(result, expected)

    @patch('scans.scan_task.netifaces')
    @patch('scans.scan_task.Scan')
    @patch('scans.scan_task.time.time', MagicMock(return_value=67))
    @patch('scans.scan_task.cfg', new_callable=Config)
    def test_special_ports(self, cfg, scan, netifaces):
        cfg['service.scans.physical'] = True
        interfaces = [MagicMock(), MagicMock()]
        netifaces.interfaces.return_value = interfaces

        netifaces.ifaddresses.side_effect = ((netifaces.AF_INET, ), ())

        result = self.task._get_special_ports()
        expected = PhysicalPort()
        expected.interface = interfaces[0]
        expected.scan = scan.return_values
        scan.assert_called_once_with(start=67)
        self.assertEqual(result, [expected])

    @gen_test
    async def test_call(self):
        with self.assertRaises(NotImplementedError):
            await self.task()
