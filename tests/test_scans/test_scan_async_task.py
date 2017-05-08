import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call
from urllib.error import URLError

import time
from croniter import croniter
from netaddr import IPSet
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from scans.scan_async_task import ScanAsyncTask
from structs import Node, PhysicalPort, Port, TransportProtocol, ScanStatus
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

    @patch('scans.scan_async_task.ScanAsyncTask._get_topdis_nodes', MagicMock(return_value=[]))
    @patch('scans.scan_async_task.croniter', MagicMock(return_value=croniter('* * * * *', time.time())))
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(ScanAsyncTaskTest, self).setUp()
        cfg._cfg = {
            'portdetection': {
                'scan_cron': '* * * * *',
                'tools_cron': '* * * * *'
            }
        }
        self.urllib_response = MagicMock()
        self.urllib_response.read = MagicMock()
        self.urllib_response.read.return_value = self.TODIS_RESPONSE
        self.urllib_response.headers.get_content_charset = MagicMock(return_value='utf-8')
        self.thread = ScanAsyncTask(aucote=MagicMock(storage=MagicMock()))
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

    @patch('scans.scan_async_task.cfg.get', MagicMock(side_effect=KeyError('test')))
    def test_init_with_exception(self):
        self.assertRaises(SystemExit, ScanAsyncTask, aucote=MagicMock())

    @patch('scans.scan_async_task.http.urlopen')
    @patch('scans.scan_async_task.cfg.get', MagicMock())
    def test_getting_nodes(self, urllib):
        urllib.return_value = self.urllib_response

        nodes = self.thread._get_topdis_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')

    @patch('scans.scan_async_task.http.urlopen')
    @patch('scans.scan_async_task.cfg.get', MagicMock())
    def test_getting_nodes_cannot_connect_to_topdis(self, urllib):
        urllib.side_effect = URLError('')
        result = self.thread._get_topdis_nodes()
        expected = []

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.http.urlopen')
    def test_getting_nodes_unknown_exception(self, urllib):
        urllib.side_effect = Exception

        self.assertRaises(Exception, ScanAsyncTask._get_topdis_nodes)

    @patch('scans.scan_async_task.ScanAsyncTask._get_topdis_nodes')
    @patch('scans.scan_async_task.cfg.get', MagicMock(return_value='5s'))
    @patch('scans.scan_async_task.parse_period', MagicMock(return_value=5))
    def test_get_nodes_for_scanning(self, mock_get_nodes):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)

        nodes = [node_1, node_2,]
        mock_get_nodes.return_value=nodes

        self.thread.storage.get_nodes = MagicMock(return_value=[node_2, node_3])

        result = self.thread._get_nodes_for_scanning()
        expected = [node_1]

        self.assertListEqual(result, expected)

    @patch('scans.scan_async_task.AsyncTaskManager.start')
    def test_run_as_service(self, mock_start):
        self.thread.scheduler = MagicMock()
        self.thread.as_service = True

        self.thread._periodical_tools_scan = MagicMock()
        self.thread._periodical_scan_callback = MagicMock()
        self.thread._ioloop = MagicMock()

        self.thread.run()

        mock_start.called_once_with()

    @patch('scans.scan_async_task.IOLoop')
    @patch('scans.scan_async_task.partial')
    def test_run_as_non_service(self, mock_partial, mock_ioloop):
        self.thread.as_service = False
        self.thread._get_nodes_for_scanning = MagicMock()
        self.thread.scheduler = MagicMock()
        self.thread.run_scan = MagicMock()
        self.thread._get_nodes_for_scanning = MagicMock()

        self.thread.run()

        mock_partial.assert_called_once_with(self.thread.run_scan, self.thread._get_nodes_for_scanning.return_value)
        mock_ioloop.current.return_value.add_callback.assert_called_once_with(mock_partial.return_value)

    @patch('scans.scan_async_task.IOLoop')
    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_service(self, cfg, mock_executor, mock_masscan, mock_nmap, mock_netiface, mock_ioloop):
        cfg._cfg = {
            'service': {
                'scans': {
                    'physical': True,
                }
            },
            'portdetection': {
                'ports': {
                    'include': ['T:0-65535', 'U:0-65535', 'S:0-65535'],
                    'exclude': ''
                }
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
        self.assertFalse(mock_ioloop.current.return_value.current.called)

    @patch('scans.scan_async_task.IOLoop')
    @patch('scans.scan_async_task.netifaces')
    @patch('scans.scan_async_task.PortsScan')
    @patch('scans.scan_async_task.MasscanPorts')
    @patch('scans.scan_async_task.Executor')
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service(self, cfg, mock_executor, mock_masscan, mock_nmap, mock_netiface, mock_loop):
        cfg._cfg = {
            'service': {
                'scans': {
                    'physical': False,
                }
            },
            'portdetection': {
                'ports': {
                    'include': ['T:0-65535', 'U:0-65535', 'S:0-65535'],
                    'exclude': ''
                },
            }
        }
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.thread.as_service = False
        self.thread.aucote = MagicMock()

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
        mock_executor.assert_called_once_with(aucote=self.thread.aucote, nodes=[port_masscan, port_nmap],
                                              scan_only=False)
        mock_loop.current.return_value.stop.assert_called_once_with()

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
            'portdetection': {
                'ports': {
                    'include': ['T:0-65535', 'U:0-65535', 'S:0-65535'],
                    'exclude': ''
                },
                'networks': {
                    'exclude': [],
                    'include': '0.0.0.0/0'
                },
                'scan_enable': True
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

    @gen_test
    def test_run_scan_without_nodes(self):
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)

    @patch('scans.scan_async_task.IOLoop')
    @gen_test
    def test_run_scan_as_non_service_without_nodes(self, mock_loop):
        self.thread.as_service = False
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)
        mock_loop.current.return_value.stop.assert_called_once_with()

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

    @patch('scans.scan_async_task.http.urlopen')
    @patch('scans.scan_async_task.cfg.get', MagicMock())
    def test_scan_time_init(self, urllib):
        urllib.return_value = self.urllib_response

        result = self.thread._get_topdis_nodes()
        expected = 1470915752.842891

        self.assertEqual(result[0].scan.start, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    def test_periodical_scan(self, cfg):
        cfg._cfg = {'portdetection': {'scan_enable': True}}
        nodes = MagicMock()
        self.thread._get_nodes_for_scanning = MagicMock(return_value=nodes)
        self.thread.run_scan = MagicMock()

        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.thread.run_scan.return_value = future_run_scan

        yield self.thread._scan()
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
        self.thread._get_topdis_nodes = MagicMock(return_value=nodes)

        yield self.thread._run_tools()

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports)
        self.thread.aucote.add_task.assert_called_once_with(mock_executor.return_value)

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
    def test_update_scan_status_to_in_progress(self, cfg):
        cfg.toucan = MagicMock()
        self.thread.scan_start = 17
        self.thread.update_scan_status(ScanStatus.IN_PROGRESS)

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
    def test_update_scan_status_to_idle(self, cfg):
        cfg.toucan = MagicMock()
        self.thread.scan_start = 17
        self.thread.update_scan_status(ScanStatus.IDLE)

        expected = {
            'previous_scan': 57,
            'next_scan': 75,
            'scan_start': 17,
            'scan_duration': 283,
            'status': "IDLE"
        }

        cfg.toucan.put.assert_called_once_with('portdetection.status', expected)
