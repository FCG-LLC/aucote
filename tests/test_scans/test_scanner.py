import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock

from netaddr import IPSet
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from scans.scanner import Scanner
from structs import Node, PhysicalPort, Port, TransportProtocol, ScanStatus, CPEType
from utils import Config
from utils.async_task_manager import AsyncTaskManager


class ScannerTest(AsyncTestCase):
    @patch('scans.scanner.Scanner._get_topdis_nodes', MagicMock(return_value=[]))
    @patch('scans.scanner.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(ScannerTest, self).setUp()
        self.cfg = {
            'portdetection': {
                'test_name': {
                    'scan_enabled': True,
                    'scan_type': 'LIVE',
                    'live_scan': {
                        'min_time_gap': 0,
                    },
                    'periodic_scan': {
                        'cron': '* * * * *'
                    },
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
        self.req_future = Future()
        self.aucote = MagicMock(storage=MagicMock())
        atm_stop_future = Future()
        self.atm_stop = MagicMock()
        atm_stop_future.set_result(self.atm_stop)
        self.aucote.async_task_manager.stop.return_value = atm_stop_future

        self.task = Scanner(aucote=self.aucote)
        self.task._cron_tasks = {
            1: MagicMock(),
            2: MagicMock()
        }
        self.task_manager = AsyncTaskManager.instance()
        self.task_manager.run_tasks = {
            '_run_tools': False,
            '_scan': False
        }

        self.task.NAME = "test_name"

    def tearDown(self):
        AsyncTaskManager.instance().clear()

    @patch('scans.scanner.Scanner.scanners', new_callable=PropertyMock)
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service(self, cfg, mock_executor, scanners):
        cfg._cfg = self.cfg
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)
        mock_nmap = MagicMock()
        mock_masscan = MagicMock()

        self.task._get_nodes_for_scanning = MagicMock(return_value=[node_1])
        self.task._get_networks_list = MagicMock(return_value=IPSet(['127.0.0.2/31']))
        self.task.as_service = False

        port_masscan = Port(transport_protocol=TransportProtocol.UDP, number=17, node=node_1)
        port_nmap = Port(transport_protocol=TransportProtocol.UDP, number=17, node=node_1)
        port_physical = PhysicalPort()

        self.task._filter_out_ports = MagicMock(return_value=[port_masscan, port_nmap])
        self.task._get_special_ports = MagicMock(return_value=[port_physical])

        mock_masscan.scan_ports.return_value = Future()
        mock_masscan.scan_ports.return_value.set_result([port_masscan])

        mock_nmap.scan_ports.return_value = Future()
        mock_nmap.scan_ports.return_value.set_result([port_nmap])

        scanners.return_value = {
            self.task.IPV4: [mock_masscan],
            self.task.IPV6: [mock_nmap]
        }

        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scan_only=False)
        mock_executor.assert_called_once_with(aucote=self.task.aucote, ports=[port_masscan, port_nmap, port_physical],
                                              scan_only=False)
        self.task._filter_out_ports.assert_called_once_with([port_masscan, port_nmap])

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_without_nodes(self, cfg):
        cfg['portdetection._internal.nmap_udp'] = False
        self.task._get_nodes_for_scanning = MagicMock(return_value=[])
        self.task._get_networks_list = MagicMock()
        self.task._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.task.run_scan(self.task._get_nodes_for_scanning(), scan_only=False)
        self.assertFalse(self.task.storage.save_nodes.called)

    @patch('scans.scanner.cfg.get', MagicMock(side_effect=KeyError("test")))
    def test_get_networks_list_no_cfg(self):
        self.assertRaises(SystemExit, self.task._get_networks_list)

    def test_current_scan_getter(self):
        expected = [MagicMock(), MagicMock()]
        self.task._current_scan = expected
        result = self.task.current_scan

        self.assertCountEqual(result, expected)
        self.assertNotEqual(id(result), id(expected))

    @patch('scans.scanner.Scanner.next_scan', 75)
    @patch('scans.scanner.Scanner.previous_scan', 57)
    @patch('scans.scanner.cfg', new_callable=Config)
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
                    'test_name': {
                        'previous_scan_start': 57,
                        'next_scan_start': 75,
                        'scan_start': 17,
                        'previous_scan_duration': 0,
                        'code': "IN PROGRESS"
                    }
                }
            }
        }

        cfg.toucan.push_config.assert_called_once_with(expected, overwrite=True)

    @patch('scans.scanner.Scanner.next_scan', 75)
    @patch('scans.scanner.Scanner.previous_scan', 57)
    @patch('scans.scanner.time.time', MagicMock(return_value=300))
    @patch('scans.scanner.cfg', new_callable=Config)
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
                    'test_name': {
                        'previous_scan_start': 57,
                        'next_scan_start': 75,
                        'scan_start': 17,
                        'previous_scan_duration': 283,
                        'code': "IDLE"
                    }
                }
            }
        }

        cfg.toucan.push_config.assert_called_once_with(expected, overwrite=True)

    def test_scanners(self):
        with self.assertRaises(NotImplementedError):
            self.task.scanners

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_call(self, cfg):
        cfg['portdetection.test_name.scan_enabled'] = True
        nodes = MagicMock()
        self.task._get_nodes_for_scanning = MagicMock(return_value=Future())
        self.task._get_nodes_for_scanning.return_value.set_result(nodes)
        self.task.run_scan = MagicMock(return_value=Future())
        self.task.run_scan.return_value.set_result(MagicMock())

        await self.task()

        self.task._get_nodes_for_scanning.assert_called_once_with(timestamp=None)
        self.task.run_scan.assert_called_once_with(nodes=nodes, scan_only=self.task._scan_only)

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_call_disable(self, cfg):
        cfg['portdetection.test_name.scan_enabled'] = False
        nodes = MagicMock()
        self.task._get_nodes_for_scanning = MagicMock()

        await self.task()

        self.assertFalse(self.task._get_nodes_for_scanning.called)
