import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call

import time
from urllib.error import URLError

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
                'scan_cron': '* * * * *',
                'tools_cron': '* * * * *'
            },
            'topdis': {
                'api': {
                    'host': '',
                    'port': ''
                }
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

        self.thread = ScanAsyncTask(aucote=self.aucote)
        self.thread._cron_tasks = {
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

        nodes = await self.thread._get_topdis_nodes()

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

        nodes = await self.thread._get_topdis_nodes()
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

        nodes = await self.thread._get_topdis_nodes()
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

        nodes = await self.thread._get_topdis_nodes()
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
        http_client.instance().get.side_effect = URLError('')
        result = await self.thread._get_topdis_nodes()
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
        cfg._cfg = {
            'portdetection': {
                'scan_interval': '5s',
                'networks': {
                    'include': ['127.0.0.2/31']
                }
            }
        }
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)

        nodes = [node_1, node_2, node_3]
        future = Future()
        future.set_result(nodes)
        mock_get_nodes.return_value = future

        self.thread.storage.get_nodes = MagicMock(return_value=[node_2])

        result = await self.thread._get_nodes_for_scanning()
        expected = [node_3]

        self.assertListEqual(result, expected)

    @gen_test
    async def test_run_as_service(self):
        self.thread.scheduler = MagicMock()
        self.thread.as_service = True

        self.thread._periodical_tools_scan = MagicMock()
        self.thread._periodical_scan_callback = MagicMock()
        self.thread._ioloop = MagicMock()

        await self.thread.run()
        self.thread.aucote.async_task_manager.start.assert_called_once_with()

    @gen_test
    async def test_run_as_non_service(self):
        self.thread.as_service = False
        expected = MagicMock()
        future = Future()
        future.set_result(expected)
        self.thread._get_nodes_for_scanning = MagicMock(return_value=future)
        self.thread.scheduler = MagicMock()
        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.thread.run_scan = MagicMock(return_value=future_run_scan)

        await self.thread.run()
        self.thread.run_scan.assert_called_once_with(expected)


    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_service(self, cfg, mock_executor, mock_masscan, mock_nmap, mock_netiface):
        cfg._cfg = {
            'service': {
                'scans': {
                    'physical': True,
                }
            },
            'topdis': {
                'fetch_os': False
            },
            'portdetection': {
                'ports': {
                    'tcp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'udp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'sctp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'nmap_udp': False
            }
        }
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.thread.aucote = MagicMock()

        ports_masscan = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap_udp = [Port(node=MagicMock(), transport_protocol=TransportProtocol.UDP, number=80)]

        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        future_masscan = Future()
        future_masscan.set_result(ports_masscan)
        mock_masscan.return_value.scan_ports.return_value = future_masscan

        future_nmap = Future()
        future_nmap.set_result(ports_nmap)

        future_nmap_udp = Future()
        future_nmap_udp.set_result(ports_nmap_udp)

        mock_nmap.return_value.scan_ports.side_effect = (future_nmap, future_nmap_udp)

        port = PhysicalPort()
        port.interface = 'test'

        ports = [ports_masscan[0], ports_nmap[0],
                 # ports_nmap_udp[0],
                 port]

        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports, scan_only=False)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service(self, cfg, mock_executor, mock_masscan, mock_nmap, mock_netiface):
        cfg._cfg = {
            'service': {
                'scans': {
                    'physical': False,
                }
            },
            'topdis': {
                'fetch_os': False
            },
            'portdetection': {
                'ports': {
                    'tcp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'udp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'sctp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'nmap_udp': False
            }
        }
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.thread.as_service = False

        port_masscan = Port(transport_protocol=TransportProtocol.UDP, number=17, node=node_1)
        port_nmap = Port(transport_protocol=TransportProtocol.UDP, number=17, node=node_1)
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        future_masscan = Future()
        future_masscan.set_result([port_masscan])
        mock_masscan.return_value.scan_ports.return_value = future_masscan

        future_nmap = Future()
        future_nmap.set_result([port_nmap])
        mock_nmap.return_value.scan_ports.return_value = future_nmap

        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=[port_masscan, port_nmap],
                                              scan_only=False)
        self.thread.aucote.async_task_manager.stop.assert_called_once_with()

    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_scan_only(self, cfg, mock_executor, mock_masscan, mock_nmap, mock_netiface):
        cfg._cfg = {
            'service': {
                'scans': {
                    'physical': True,
                }
            },
            'topdis': {
                'fetch_os': False
            },
            'portdetection': {
                'ports': {
                    'tcp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'udp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'sctp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'networks': {
                    'exclude': [],
                    'include': '0.0.0.0/0'
                },
                'scan_enable': True,
                'nmap_udp': False
            }
        }
        self.cfg = cfg
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['0.0.0.0/0']))
        self.thread.aucote = MagicMock()

        ports_masscan = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        future_masscan = Future()
        future_masscan.set_result(ports_masscan)
        mock_masscan.return_value.scan_ports.return_value = future_masscan

        future_nmap = Future()
        future_nmap.set_result(ports_nmap)
        mock_nmap.return_value.scan_ports.return_value = future_nmap

        port = PhysicalPort()
        port.interface = 'test'

        ports = [ports_masscan[0], ports_nmap[0],
                 # ports_nmap[0],
                 port]

        scan_only = MagicMock()

        yield self.thread.run_scan(self.thread._get_nodes_for_scanning(), scan_only=scan_only)

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports, scan_only=scan_only)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_scan_only_with_udp(self, cfg, mock_executor, mock_masscan, mock_nmap, mock_netiface):
        cfg._cfg = {
            'service': {
                'scans': {
                    'physical': False,
                }
            },
            'portdetection': {
                'ports': {
                    'tcp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'udp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                    'sctp': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'networks': {
                    'exclude': [],
                    'include': '0.0.0.0/0'
                },
                'scan_enable': True,
                'nmap_udp': True
            }
        }
        self.cfg = cfg
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['0.0.0.0/0']))
        self.thread.aucote = MagicMock()

        ports_masscan = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        ports_nmap = [Port(node=MagicMock(), transport_protocol=TransportProtocol.TCP, number=80)]
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        future_masscan = Future()
        future_masscan.set_result(ports_masscan)
        mock_masscan.return_value.scan_ports.return_value = future_masscan

        future_nmap = Future()
        future_nmap.set_result(ports_nmap)
        mock_nmap.return_value.scan_ports.return_value = future_nmap

        ports = [ports_masscan[0], ports_nmap[0],ports_nmap[0]]
        scan_only = MagicMock()

        yield self.thread.run_scan(self.thread._get_nodes_for_scanning(), scan_only=scan_only)

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports, scan_only=scan_only)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_without_nodes(self, cfg):
        cfg._cfg = {
            'portdetection': {
                'nmap_udp': False
            }
        }
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service_without_nodes(self, cfg):
        cfg._cfg = {
            'portdetection': {
                'nmap_udp': False
            }
        }
        self.thread.as_service = False
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)
        self.thread.aucote.async_task_manager.stop.assert_called_once_with()

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_get_networks_list(self, cfg):
        cfg._cfg = {
            'portdetection': {
                'networks': {
                    'include': [
                        '127.0.0.1/24',
                        '128.0.0.1/13'
                    ]
                }
            }
        }
        result = self.thread._get_networks_list()
        expected = IPSet(['127.0.0.1/24', '128.0.0.1/13'])

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg.get', MagicMock(side_effect=KeyError("test")))
    def test_get_networks_list_no_cfg(self):

        self.assertRaises(SystemExit, self.thread._get_networks_list)

    @patch('scans.scan_async_task.HTTPClient')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_scan_time_init(self, cfg, http_client):
        cfg._cfg = self.cfg
        self.req_future.set_result(self.http_client_response)
        http_client.instance().get.return_value = self.req_future

        result = await self.thread._get_topdis_nodes()
        expected = 1470915752.842891

        self.assertEqual(result[0].scan.start, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_periodical_scan(self, cfg):
        cfg._cfg = {'portdetection': {'scan_enable': True}}
        nodes = MagicMock()
        future = Future()
        future.set_result(nodes)
        self.thread._get_nodes_for_scanning = MagicMock(return_value=future)

        future = Future()
        future.set_result(MagicMock())
        self.thread.run_scan = MagicMock(return_value=future)

        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.thread.run_scan.return_value = future_run_scan

        await self.thread._scan()
        self.thread._get_nodes_for_scanning.assert_called_once_with(timestamp=None)
        self.thread.run_scan.assert_called_once_with(nodes, scan_only=True)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_disable_periodical_scan(self, cfg):
        cfg._cfg = {'portdetection': {'scan_enable': False}}
        self.thread._get_nodes_for_scanning = MagicMock()

        yield self.thread._scan()
        self.assertFalse(self.thread._get_nodes_for_scanning.called)

    def test_current_scan_getter(self):
        expected = [MagicMock(), MagicMock()]
        self.thread._current_scan = expected
        result = self.thread.current_scan

        self.assertCountEqual(result, expected)
        self.assertNotEqual(id(result), id(expected))

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_previous_scan(self, mock_cfg):
        mock_cfg._cfg = {
            'portdetection': {
                'scan_cron': '* * * * *',
                'tools_cron': '* * * * *',
            }
        }

        expected = 480
        result = self.thread.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=1595))
    def test_previous_tools_scan(self, mock_cfg):
        mock_cfg._cfg = {
            'portdetection': {
                'cron': '* * * * *',
                'tools_cron': '*/8 * * * *',
            }
        }

        expected = 1440
        result = self.thread.previous_tool_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_previous_scan_second_test(self, mock_cfg):
        mock_cfg._cfg = {
            'portdetection': {
                'scan_cron': '*/12 * * * *',
                'tools_cron': '*/12 * * * *'
            }
        }

        expected = 0
        result = self.thread.previous_scan

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
        self.thread.storage.get_ports_by_nodes.return_value = ports

        result = self.thread.get_ports_for_script_scan(nodes)

        self.assertEqual(result, ports)
        self.thread.storage.get_ports_by_nodes.assert_has_calls([call(nodes=nodes, timestamp=100)])

    @patch('scans.scan_async_task.Executor')
    @gen_test
    def test_run_scripts(self, mock_executor):
        ports = MagicMock()
        nodes = [MagicMock(), MagicMock(), MagicMock()]

        self.thread.get_ports_for_script_scan = MagicMock(return_value=ports)
        future_nodes = Future()
        future_nodes.set_result(nodes)
        self.thread._get_topdis_nodes = MagicMock(return_value=future_nodes)

        yield self.thread._run_tools()

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports)
        self.thread.aucote.add_async_task.assert_called_once_with(mock_executor.return_value)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_next_scan(self, mock_cfg):
        mock_cfg._cfg = {
            'portdetection': {
                'scan_cron': '*/5 * * * *',
                'tools_cron': '*/12 * * * *'
            }
        }

        expected = 600
        result = self.thread.next_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_next_tool_scan(self, mock_cfg):
        mock_cfg._cfg = {
            'portdetection': {
                'cron': '*/12 * * * *',
                'tools_cron': '*/12 * * * *'
            }
        }

        expected = 720
        result = self.thread.next_tool_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.ScanAsyncTask.next_scan', 75)
    @patch('scans.scan_async_task.ScanAsyncTask.previous_scan', 57)
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_in_progress(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.put.return_value = Future()
        cfg.toucan.put.return_value.set_result(MagicMock())

        self.thread.scan_start = 17
        await self.thread.update_scan_status(ScanStatus.IN_PROGRESS)

        expected = {
            'previous_scan': 57,
            'next_scan': 75,
            'scan_start': 17,
            'scan_duration': None,
            'status': "IN PROGRESS"
        }

        cfg.toucan.put.assert_called_once_with('portdetection.status', expected)

    @patch('scans.scan_async_task.ScanAsyncTask.next_scan', 75)
    @patch('scans.scan_async_task.ScanAsyncTask.previous_scan', 57)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=300))
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_idle(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.put.return_value = Future()
        cfg.toucan.put.return_value.set_result(MagicMock())

        self.thread.scan_start = 17
        await self.thread.update_scan_status(ScanStatus.IDLE)

        expected = {
            'previous_scan': 57,
            'next_scan': 75,
            'scan_start': 17,
            'scan_duration': 283,
            'status': "IDLE"
        }

        cfg.toucan.put.assert_called_once_with('portdetection.status', expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron(self, cfg):
        expected = "* * * * */45"
        cfg['portdetection.scan_cron'] = expected
        result = self.thread._scan_cron()
        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_tools_cron(self, cfg):
        expected = "* * * * */45"
        cfg['portdetection.tools_cron'] = expected
        result = self.thread._tools_cron()
        self.assertEqual(result, expected)

    def test_shutdown_condition(self):
        self.assertEqual(self.thread.shutdown_condition, self.thread._shutdown_condition)
