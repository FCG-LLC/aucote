import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call

import time
from tornado.httpclient import HTTPError

from cpe import CPE
from croniter import croniter
from netaddr import IPSet
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from scans.scan_async_task import ScanAsyncTask
from structs import Node, PhysicalPort, Scan, Port, TransportProtocol, ScanStatus, CPEType
from utils import Config
from utils.async_task_manager import AsyncTaskManager


class ScanAsyncTaskTest(AsyncTestCase):
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

    @patch('scans.scan_async_task.ScanAsyncTask._get_topdis_nodes', MagicMock(return_value=[]))
    @patch('scans.scan_async_task.croniter', MagicMock(return_value=croniter('* * * * *', time.time())))
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(ScanAsyncTaskTest, self).setUp()
        self.cfg = {
            'portdetection': {
                'scan_type': 'LIVE',
                'live_scan': {
                    'min_time_gap': 0,
                },
                'periodic_scan': {
                    'cron': '* * * * *'
                },
                '_internal': {
                    'tools_cron': '* * * * *',
                    'nmap_udp': False
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

        self.task = ScanAsyncTask(aucote=self.aucote)
        self.task._cron_tasks = {
            1: MagicMock(),
            2: MagicMock()
        }
        self.task_manager = AsyncTaskManager.instance()
        self.task_manager.run_tasks = {
            '_run_tools': False,
            '_scan': False
        }

    def tearDown(self):
        AsyncTaskManager.instance().clear()

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
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

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
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

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.Service.build_cpe')
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

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.Service.build_cpe')
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

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_getting_nodes_cannot_connect_to_topdis(self, cfg, http_client):
        cfg._cfg = self.cfg
        http_client.instance().get.side_effect = HTTPError('')
        result = await self.task._get_topdis_nodes()
        expected = []

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_getting_nodes_connection_error_to_topdis(self, cfg, http_client):
        cfg._cfg = self.cfg
        http_client.instance().get.side_effect = ConnectionError('')
        result = await self.task._get_topdis_nodes()
        expected = []

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.HTTPClient')
    @gen_test
    async def test_getting_nodes_unknown_exception(self, http_client):
        http_client.instance().get.side_effect = Exception
        with self.assertRaises(Exception):
            await ScanAsyncTask._get_topdis_nodes

    @patch('scans.scan_async_task.ScanAsyncTask._get_topdis_nodes')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.parse_period', MagicMock(return_value=5))
    @gen_test
    async def test_get_nodes_for_scanning(self, cfg, mock_get_nodes):
        cfg._cfg = self.cfg
        cfg['portdetection.networks.include'] = ['127.0.0.2/31']

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

    @gen_test
    async def test_run_as_service(self):
        self.task.scheduler = MagicMock()
        self.task.as_service = True

        self.task._periodical_tools_scan = MagicMock()
        self.task._periodical_scan_callback = MagicMock()
        self.task._ioloop = MagicMock()

        await self.task.run()
        self.task.aucote.async_task_manager.start.assert_called_once_with()

    @gen_test
    async def test_run_as_non_service(self):
        self.task._get_scanners = MagicMock()
        self.task.as_service = False
        expected = MagicMock()
        future = Future()
        future.set_result(expected)
        self.task._get_nodes_for_scanning = MagicMock(return_value=future)
        self.task.scheduler = MagicMock()
        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.task.run_scan = MagicMock(return_value=future_run_scan)

        await self.task.run()
        self.task.run_scan.assert_called_once_with(expected, scan_only=False, scanners=self.task._get_scanners())

    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_service(self, cfg, mock_executor, mock_netiface):
        cfg._cfg = self.cfg
        cfg['service.scans.physical'] = True
        cfg['portdetection.ports.tcp.include'] = ['0-65535']
        cfg['portdetection.ports.udp.include'] = ['0-65535']
        cfg['portdetection.ports.sctp.include'] = ['0-65535']

        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)
        mock_masscan = MagicMock()
        mock_nmap = MagicMock()
        mock_nmap_udp = MagicMock()

        self.task._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.task._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.task.aucote = MagicMock()

        ports_masscan = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap_udp = [Port(node=MagicMock(), transport_protocol=TransportProtocol.UDP, number=80)]

        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        mock_masscan.scan_ports.return_value = Future()
        mock_masscan.scan_ports.return_value.set_result(ports_masscan)

        mock_nmap.scan_ports.return_value = Future()
        mock_nmap.scan_ports.return_value.set_result(ports_nmap)

        mock_nmap_udp.scan_ports.return_value = Future()
        mock_nmap_udp.scan_ports.return_value.set_result(ports_nmap_udp)

        scanners = {
            self.task.IPV4: [mock_masscan, mock_nmap_udp],
            self.task.IPV6: [mock_nmap]
        }

        port = PhysicalPort()
        port.interface = 'test'

        ports = [ports_masscan[0], ports_nmap_udp[0], ports_nmap[0], port]

        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scanners=scanners, scan_only=False)

        mock_executor.assert_called_once_with(aucote=self.task.aucote, ports=ports, scan_only=False)
        self.task.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service(self, cfg, mock_executor, mock_netiface):
        cfg._cfg = self.cfg
        cfg['service.scans.physical'] = False
        cfg['portdetection.ports.tcp.include'] = ['0-65535']
        cfg['portdetection.ports.udp.include'] = ['0-65535']
        cfg['portdetection.ports.sctp.include'] = ['0-65535']

        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)
        mock_nmap = MagicMock()
        mock_masscan = MagicMock()

        self.task._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.task._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.task.as_service = False

        port_masscan = Port(transport_protocol=TransportProtocol.UDP, number=17, node=node_1)
        port_nmap = Port(transport_protocol=TransportProtocol.UDP, number=17, node=node_1)
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        mock_masscan.scan_ports.return_value = Future()
        mock_masscan.scan_ports.return_value.set_result([port_masscan])

        mock_nmap.scan_ports.return_value = Future()
        mock_nmap.scan_ports.return_value.set_result([port_nmap])

        scanners = {
            self.task.IPV4: [mock_masscan],
            self.task.IPV6: [mock_nmap]
        }
        self.task._get_scanners = MagicMock(return_value=scanners)

        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scan_only=False, scanners=scanners)
        mock_executor.assert_called_once_with(aucote=self.task.aucote, ports=[port_masscan, port_nmap],
                                              scan_only=False)
        self.task.aucote.async_task_manager.stop.assert_called_once_with()

    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_scan_only(self, cfg, mock_executor, mock_netiface):
        cfg._cfg = self.cfg
        cfg['service.scans.physical'] = True
        cfg['portdetection.ports.tcp.include'] = ['0-65535']
        cfg['portdetection.ports.udp.include'] = ['0-65535']
        cfg['portdetection.ports.sctp.include'] = ['0-65535']
        cfg['portdetection.ports.networks.include'] = ['0.0.0.0/0']

        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)
        mock_masscan = MagicMock()
        mock_nmap = MagicMock()

        self.task._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.task._get_networks_list = MagicMock(return_value=IPSet(['0.0.0.0/0']))
        self.task.aucote = MagicMock()

        ports_masscan = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        mock_masscan.scan_ports.return_value = Future()
        mock_masscan.scan_ports.return_value.set_result(ports_masscan)

        mock_nmap.scan_ports.return_value = Future()
        mock_nmap.scan_ports.return_value.set_result(ports_nmap)

        scanners = {
            self.task.IPV4: [mock_masscan],
            self.task.IPV6: [mock_nmap]
        }
        self.task._get_scanners = MagicMock(return_value=scanners)

        port = PhysicalPort()
        port.interface = 'test'

        ports = [ports_masscan[0], ports_nmap[0],
                 # ports_nmap[0],
                 port]

        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scan_only=False, scanners=scanners)

        mock_executor.assert_called_once_with(aucote=self.task.aucote, ports=ports, scan_only=False)
        self.task.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_without_nodes(self, cfg):
        cfg['portdetection._internal.nmap_udp'] = False
        self.task._get_nodes_for_scanning = MagicMock(return_value=[])
        self.task._get_networks_list = MagicMock()
        self.task._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scan_only=False, scanners=MagicMock())
        self.assertFalse(self.task.storage.save_nodes.called)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service_without_nodes(self, cfg):
        cfg['portdetection._internal.nmap_udp'] = False
        self.task.as_service = False
        self.task._get_nodes_for_scanning = MagicMock(return_value=[])
        self.task._get_networks_list = MagicMock()
        self.task._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scan_only=False, scanners=MagicMock())
        self.assertFalse(self.task.storage.save_nodes.called)
        self.task.aucote.async_task_manager.stop.assert_called_once_with()

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_get_networks_list(self, cfg):
        cfg['portdetection.networks.include'] = ['127.0.0.1/24', '128.0.0.1/13']
        result = self.task._get_networks_list()
        expected = IPSet(['127.0.0.1/24', '128.0.0.1/13'])

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg.get', MagicMock(side_effect=KeyError("test")))
    def test_get_networks_list_no_cfg(self):

        self.assertRaises(SystemExit, self.task._get_networks_list)

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_scan_time_init(self, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(self.http_client_response)
        http_client.instance().get.return_value = self.req_future

        result = await self.task._get_topdis_nodes()
        expected = 1470915752.842891

        self.assertEqual(result[0].scan.start, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_periodical_scan(self, cfg):
        self.task._get_scanners = MagicMock()
        cfg._cfg = {'portdetection': {'scan_enabled': True}}
        nodes = MagicMock()
        future = Future()
        future.set_result(nodes)
        self.task._get_nodes_for_scanning = MagicMock(return_value=future)

        future = Future()
        future.set_result(MagicMock())
        self.task.run_scan = MagicMock(return_value=future)

        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.task.run_scan.return_value = future_run_scan

        await self.task._scan()
        self.task._get_nodes_for_scanning.assert_called_once_with(timestamp=None)
        self.task.run_scan.assert_called_once_with(nodes, scan_only=True, scanners=self.task._get_scanners())

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_disable_periodical_scan(self, cfg):
        cfg._cfg = {'portdetection': {'scan_enabled': False}}
        self.task._get_nodes_for_scanning = MagicMock()

        yield self.task._scan()
        self.assertFalse(self.task._get_nodes_for_scanning.called)

    def test_current_scan_getter(self):
        expected = [MagicMock(), MagicMock()]
        self.task._current_scan = expected
        result = self.task.current_scan

        self.assertCountEqual(result, expected)
        self.assertNotEqual(id(result), id(expected))

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_previous_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.scan_type'] = 'PERIODIC'
        cfg['portdetection.periodic_scan.cron'] = '* * * * *'

        expected = 480
        result = self.task.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=1595))
    def test_previous_tools_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection._internal.tools_cron'] = '*/8 * * * *'

        expected = 1440
        result = self.task.previous_tool_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_previous_scan_second_test(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.scan_type'] = 'PERIODIC'
        cfg['portdetection.periodic_scan.cron'] = '*/12 * * * *'

        expected = 0
        result = self.task.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.ScanAsyncTask.previous_tool_scan', new_callable=PropertyMock)
    def test_get_ports_for_script_scan(self, mock_previous):
        nodes = [MagicMock(), MagicMock(), MagicMock()]
        mock_previous.return_value = 100
        ports = [
            MagicMock(),
            MagicMock(),
            MagicMock()
        ]
        self.task.storage.get_ports_by_nodes.return_value = ports

        result = self.task.get_ports_for_script_scan(nodes)

        self.assertEqual(result, ports)
        self.task.storage.get_ports_by_nodes.assert_has_calls([call(nodes=nodes, timestamp=100)])

    @patch('scans.scan_async_task.Executor')
    @gen_test
    def test_run_scripts(self, mock_executor):
        ports = MagicMock()
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.task.get_ports_for_script_scan = MagicMock(return_value=ports)
        future_nodes = Future()
        future_nodes.set_result(nodes)
        self.task._get_topdis_nodes = MagicMock(return_value=future_nodes)

        yield self.task._run_tools()

        mock_executor.assert_called_once_with(aucote=self.task.aucote, ports=ports)
        self.task.aucote.add_async_task.assert_called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_next_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.scan_type'] = 'PERIODIC'
        cfg['portdetection.cron'] = '*/5 * * * *'

        expected = 600
        result = self.task.next_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_next_tool_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection._internal.tools_cron'] = '*/12 * * * *'
        cfg['portdetection.cron'] = '*/12 * * * *'

        expected = 720
        result = self.task.next_tool_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.ScanAsyncTask.next_scan', 75)
    @patch('scans.scan_async_task.ScanAsyncTask.previous_scan', 57)
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_in_progress(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.push_config.return_value = Future()
        cfg.toucan.push_config.return_value.set_result(MagicMock())

        self.task.scan_start = 17
        await self.task.update_scan_status(ScanStatus.IN_PROGRESS)

        expected = {
            'portdetection': {
                'status': {
                    'previous_scan_start': 57,
                    'next_scan_start': 75,
                    'scan_start': 17,
                    'previous_scan_duration': 0,
                    'code': "IN PROGRESS"
                }
            }
        }

        cfg.toucan.push_config.assert_called_once_with(expected, overwrite=True)

    @patch('scans.scan_async_task.ScanAsyncTask.next_scan', 75)
    @patch('scans.scan_async_task.ScanAsyncTask.previous_scan', 57)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=300))
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_idle(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.push_config.return_value = Future()
        cfg.toucan.push_config.return_value.set_result(MagicMock())

        self.task.scan_start = 17
        await self.task.update_scan_status(ScanStatus.IDLE)

        expected = {
            'portdetection': {
                'status': {
                    'previous_scan_start': 57,
                    'next_scan_start': 75,
                    'scan_start': 17,
                    'previous_scan_duration': 283,
                    'code': "IDLE"
                }
            }
        }

        cfg.toucan.push_config.assert_called_once_with(expected, overwrite=True)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron(self, cfg):
        expected = "* * * * */45"
        cfg['portdetection.scan_type'] = "PERIODIC"
        cfg['portdetection.periodic_scan.cron'] = expected
        result = self.task._scan_cron()
        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_tools_cron(self, cfg):
        expected = "* * * * */45"
        cfg['portdetection.scan_type'] = "PERIODIC"
        cfg['portdetection._internal.tools_cron'] = expected
        result = self.task._tools_cron()
        self.assertEqual(result, expected)

    def test_shutdown_condition(self):
        self.assertEqual(self.task.shutdown_condition, self.task._shutdown_condition)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_interval_periodic(self, cfg):
        cfg['portdetection.scan_type'] = "PERIODIC"

        result = self.task._scan_interval()
        expected = 0

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_interval_live(self, cfg):
        cfg['portdetection.scan_type'] = "LIVE"
        cfg['portdetection.live_scan.min_time_gap'] = "5m13s"

        result = self.task._scan_interval()
        expected = 313

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron_periodic(self, cfg):
        cfg['portdetection.scan_type'] = "PERIODIC"
        cfg['portdetection.periodic_scan.cron'] = "*/2 3 */5 * *"

        result = self.task._scan_cron()
        expected = "*/2 3 */5 * *"

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron_live(self, cfg):
        cfg['portdetection.scan_type'] = "LIVE"

        result = self.task._scan_cron()
        expected = '* * * * *'

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_get_scanners(self, cfg, masscan, nmap):
        cfg._cfg = self.cfg
        result = self.task._get_scanners()
        expected = {
            self.task.IPV4: [masscan()],
            self.task.IPV6: [nmap()]
        }

        self.assertCountEqual(result, expected)

    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_get_scanners_with_udp(self, cfg, masscan, nmap):
        cfg._cfg = self.cfg
        cfg['portdetection._internal.nmap_udp'] = True
        result = self.task._get_scanners()
        expected = {
            self.task.IPV4: [masscan(), nmap()],
            self.task.IPV6: [nmap()]
        }

        self.assertCountEqual(result, expected)
