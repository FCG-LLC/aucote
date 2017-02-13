import ipaddress
import sched
from unittest import TestCase
from unittest.mock import patch, MagicMock, PropertyMock, call
from urllib.error import URLError

import time
from croniter import croniter
from netaddr import IPSet

from structs import Node, PhysicalPort
from threads.scan_thread import ScanThread
from utils import Config


class ScanThreadTest(TestCase):
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

    @patch('threads.scan_thread.ScanThread._get_topdis_nodes', MagicMock(return_value=[]))
    @patch('threads.scan_thread.croniter', MagicMock(return_value=croniter('* * * * *', time.time())))
    @patch('threads.scan_thread.cfg', new_callable=Config)
    def setUp(self, cfg):
        cfg._cfg = {
            'service': {
                'scans': {
                    'cron': '* * * * *',
                    'tools_cron': '* * * * *'
                }
            }
        }
        self.urllib_response = MagicMock()
        self.urllib_response.read = MagicMock()
        self.urllib_response.read.return_value = self.TODIS_RESPONSE
        self.urllib_response.headers.get_content_charset = MagicMock(return_value='utf-8')
        self.thread = ScanThread(aucote=MagicMock(storage=MagicMock()))
        self.thread._ioloop = MagicMock()

    @patch('threads.scan_thread.cfg.get', MagicMock(side_effect=KeyError('test')))
    def test_init_with_exception(self):
        self.assertRaises(SystemExit, ScanThread, aucote=MagicMock())

    @patch('threads.scan_thread.http.urlopen')
    @patch('threads.scan_thread.cfg.get', MagicMock())
    def test_getting_nodes(self, urllib):
        urllib.return_value = self.urllib_response

        nodes = self.thread._get_topdis_nodes()

        self.assertEqual(len(nodes), 9)
        self.assertEqual(nodes[0].id, 573)
        self.assertEqual(nodes[0].ip.exploded, '10.3.3.99')
        self.assertEqual(nodes[0].name, 'EPSON1B0407')

    @patch('threads.scan_thread.http.urlopen')
    @patch('threads.scan_thread.cfg.get', MagicMock())
    def test_getting_nodes_cannot_connect_to_topdis(self, urllib):
        urllib.side_effect = URLError('')
        result = self.thread._get_topdis_nodes()
        expected = []

        self.assertEqual(result, expected)

    @patch('threads.scan_thread.http.urlopen')
    def test_getting_nodes_unknown_exception(self, urllib):
        urllib.side_effect = Exception

        self.assertRaises(Exception, ScanThread._get_topdis_nodes)

    @patch('threads.scan_thread.ScanThread._get_topdis_nodes')
    @patch('threads.scan_thread.cfg.get', MagicMock(return_value='5s'))
    @patch('threads.scan_thread.parse_period', MagicMock(return_value=5))
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

    def test_run(self):
        self.thread.scheduler = MagicMock()
        self.thread.as_service = True
        self.thread._periodical_tools_scan = MagicMock()
        self.thread._periodical_scan_callback = MagicMock()
        self.thread._ioloop = MagicMock()

        self.thread.run()

        self.thread._periodical_tools_scan.start.assert_called_once_with()
        self.thread._periodical_scan_callback.start.assert_called_once_with()
        self.thread._ioloop.start.assert_called_once_with()

    def test_call_as_non_service(self):
        self.thread.as_service = False
        self.thread._get_nodes_for_scanning = MagicMock()
        self.thread.scheduler = MagicMock()
        self.thread.run_scan = MagicMock()

        self.thread.run()

        self.thread.run_scan.assert_called_once_with(self.thread._get_nodes_for_scanning.return_value)

    @patch('threads.scan_thread.netifaces')
    @patch('threads.scan_thread.PortsScan')
    @patch('threads.scan_thread.MasscanPorts')
    @patch('threads.scan_thread.Executor')
    @patch('threads.scan_thread.cfg.get', MagicMock(return_value=True))
    def test_run_scan(self, mock_executor, mock_masscan, mock_nmap, mock_netiface):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.thread.aucote = MagicMock()

        ports_masscan = [MagicMock()]
        ports_nmap = [MagicMock()]
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        mock_masscan.scan_ports.return_value = ports_masscan
        mock_nmap.scan_ports.return_value = ports_nmap

        port = PhysicalPort()
        port.interface = 'test'

        ports = [ports_masscan[0], ports_nmap[0], port]

        mock_masscan.return_value.scan_ports.return_value = ports_masscan
        mock_nmap.return_value.scan_ports.return_value = ports_nmap

        self.thread.run_scan(self.thread._get_nodes_for_scanning())

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, nodes=ports, scan_only=False)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    def test_run_without_nodes(self):
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)

    @patch('threads.scan_thread.cfg.get', MagicMock(return_value=MagicMock(cfg=['127.0.0.1/24', '128.0.0.1/13'])))
    def test_get_networks_list(self):
        result = self.thread._get_networks_list()
        expected = IPSet(['127.0.0.1/24', '128.0.0.1/13'])

        self.assertEqual(result, expected)

    @patch('threads.scan_thread.cfg.get', MagicMock(side_effect=KeyError("test")))
    def test_get_networks_list_no_cfg(self):

        self.assertRaises(SystemExit, self.thread._get_networks_list)

    @patch('threads.scan_thread.http.urlopen')
    @patch('threads.scan_thread.cfg.get', MagicMock())
    def test_scan_time_init(self, urllib):
        urllib.return_value = self.urllib_response

        result = self.thread._get_topdis_nodes()
        expected = 1470915752.842891

        self.assertEqual(result[0].scan.start, expected)

    @patch('threads.scan_thread.time.monotonic', MagicMock(return_value=600.5))
    @patch('threads.scan_thread.time.time', MagicMock(return_value=600.5))
    @patch('threads.scan_thread.cfg.get', MagicMock(return_value="* * * * *"))
    def test_periodical_Scan(self):
        nodes = MagicMock()
        self.thread._get_nodes_for_scanning = MagicMock(return_value=nodes)
        self.thread.run_scan = MagicMock()
        self.thread._periodical_scan()
        self.thread._get_nodes_for_scanning.assert_called_once_with(timestamp=None)
        self.thread.run_scan.assert_called_once_with(nodes, scan_only=True)

    def test_stop(self):
        self.thread._periodical_scan_callback = MagicMock()
        self.thread._periodical_tools_scan = MagicMock()
        self.thread._ioloop = MagicMock()
        self.thread.stop()
        self.thread._periodical_scan_callback.stop.assert_called_once_with()
        self.thread._periodical_tools_scan.stop.assert_called_once_with()
        self.thread._ioloop.stop.assert_called_once_with()

    def test_current_scan_getter(self):
        expected = [MagicMock(), MagicMock()]
        self.thread._current_scan = expected
        result = self.thread.current_scan

        self.assertCountEqual(result, expected)
        self.assertNotEqual(id(result), id(expected))

    @patch('threads.scan_thread.cfg', new_callable=Config)
    @patch('threads.scan_thread.time.time', MagicMock(return_value=595))
    def test_previous_scan(self, mock_cfg):
        mock_cfg._cfg = {
            'service': {
                'scans': {
                    'cron': '* * * * *'
                }
            }
        }

        expected = 480
        result = self.thread.previous_scan

        self.assertEqual(result, expected)

    @patch('threads.scan_thread.cfg', new_callable=Config)
    @patch('threads.scan_thread.time.time', MagicMock(return_value=595))
    def test_previous_scan_second_test(self, mock_cfg):
        mock_cfg._cfg = {
            'service': {
                'scans': {
                    'cron': '*/12 * * * *'
                }
            }
        }

        expected = 0
        result = self.thread.previous_scan

        self.assertEqual(result, expected)

    @patch('threads.scan_thread.netifaces')
    @patch('threads.scan_thread.PortsScan')
    @patch('threads.scan_thread.MasscanPorts')
    @patch('threads.scan_thread.Executor')
    @patch('threads.scan_thread.cfg.get', MagicMock(return_value=True))
    def test_run_scan_scan_only(self, mock_executor, mock_masscan, mock_nmap, mock_netiface):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)

        self.thread._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.thread._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.thread.aucote = MagicMock()

        ports_masscan = [MagicMock()]
        ports_nmap = [MagicMock()]
        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        mock_masscan.scan_ports.return_value = ports_masscan
        mock_nmap.scan_ports.return_value = ports_nmap

        port = PhysicalPort()
        port.interface = 'test'

        ports = [ports_masscan[0], ports_nmap[0], port]

        mock_masscan.return_value.scan_ports.return_value = ports_masscan
        mock_nmap.return_value.scan_ports.return_value = ports_nmap

        scan_only = True

        self.thread.run_scan(self.thread._get_nodes_for_scanning(), scan_only=scan_only)

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, nodes=ports, scan_only=scan_only)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('threads.scan_thread.ScanThread.previous_scan', new_callable=PropertyMock)
    def test_get_ports_for_script_scan(self, mock_previous):
        nodes = [MagicMock(), MagicMock(), MagicMock()]
        self.thread._get_topdis_nodes = MagicMock(return_value=nodes)
        mock_previous.return_value = 100
        ports = [
            MagicMock(),
            MagicMock(),
            MagicMock()
        ]
        self.thread.storage.get_ports_by_node.side_effect = (
            [ports[0], ports[1]],
            [ports[2]],
            []
        )

        result = self.thread.get_ports_for_script_scan()

        self.assertEqual(result, ports)
        self.thread.storage.get_ports_by_node.assert_has_calls([call(nodes[0], timestamp=100),
                                                                call(nodes[1], timestamp=100),
                                                                call(nodes[2], timestamp=100)])
    @patch('threads.scan_thread.Executor')
    def test_run_scripts(self, mock_executor):
        ports = MagicMock()

        self.thread.get_ports_for_script_scan = MagicMock(return_value=ports)
        self.thread._run_tools()

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, nodes=ports)
        self.thread.aucote.add_task.assert_called_once_with(mock_executor.return_value)
