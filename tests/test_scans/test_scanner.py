import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call
import time
from croniter import croniter
from netaddr import IPSet
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test
from scans.scanner import Scanner
from structs import Node, PhysicalPort, Port, TransportProtocol, ScanStatus
from utils import Config
from utils.async_task_manager import AsyncTaskManager


class ScannerTest(AsyncTestCase):
    @patch('scans.scanner.Scanner._get_topdis_nodes', MagicMock(return_value=[]))
    @patch('scans.scanner.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(ScannerTest, self).setUp()
        self.cfg = {
            'portdetection': {
                'scan_type': 'LIVE',
                'live_scan': {
                    'min_time_gap': 0,
                },
                '_internal': {
                    'tools_cron': '* * * * *'
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
        self.aucote = MagicMock(storage=MagicMock())
        atm_stop_future = Future()
        self.atm_stop = MagicMock()
        atm_stop_future.set_result(self.atm_stop)
        self.aucote.async_task_manager.stop.return_value = atm_stop_future

        self.thread = Scanner(aucote=self.aucote)
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

    @patch('scans.scanner.PhysicalPort')
    @patch('scans.scanner.netifaces')
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_service(self, cfg, mock_executor, mock_netiface, physical_port):
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
                '_internal': {
                    'nmap_udp': False
                }
            }
        }
        node_ipv4 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=1)
        node_ipv6 = Node(ip=ipaddress.ip_address('::6'), node_id=2)
        nodes = [node_ipv4, node_ipv6]

        ipv4_scanner = MagicMock()
        ipv6_scanner = MagicMock()
        scanners = {
            self.thread.IPV4: [ipv4_scanner],
            self.thread.IPV6: [ipv6_scanner]
        }

        ports_ipv4 = [Port(node=node_ipv4, transport_protocol=TransportProtocol.TCP, number=80)]
        ports_ipv6 = [Port(node=node_ipv6, transport_protocol=TransportProtocol.TCP, number=80)]

        ipv4_scanner.scan_ports.return_value = Future()
        ipv4_scanner.scan_ports.return_value.set_result(ports_ipv4)

        ipv6_scanner.scan_ports.return_value = Future()
        ipv6_scanner.scan_ports.return_value.set_result(ports_ipv6)


        mock_netiface.interfaces.return_value = ['test', 'test2']
        mock_netiface.ifaddresses.side_effect = ([mock_netiface.AF_INET], [''])

        port = physical_port()
        port.interface = 'test'

        ports = [ports_ipv4[0], ports_ipv6[0], port]

        yield self.thread.run_scan(nodes=nodes, scanners=scanners, scan_only=False, protocol=MagicMock())
        result = mock_executor.call_args_list[0][1]['ports']
        self.assertCountEqual(result, ports)

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, nodes=nodes, ports=result, scan_only=False)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scanner.Scanner.scanners', new_callable=PropertyMock)
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_periodical_scan(self, cfg, scanners):
        cfg._cfg = {'portdetection': {'scan_enabled': True}}
        nodes = MagicMock()
        future = Future()
        future.set_result(nodes)
        self.thread._get_nodes_for_scanning = MagicMock(return_value=future)

        tcp_scanner = MagicMock()
        udp_scanner = MagicMock()

        scanners.return_value = {
            TransportProtocol.TCP: tcp_scanner,
            TransportProtocol.UDP: udp_scanner
        }

        future = Future()
        future.set_result(MagicMock())
        self.thread.run_scan = MagicMock(return_value=future)

        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.thread.run_scan.return_value = future_run_scan

        await self.thread()
        self.thread.run_scan.assert_has_calls(
            [call(nodes, scan_only=True, protocol=TransportProtocol.TCP, scanners=tcp_scanner),
             call(nodes, scan_only=True, protocol=TransportProtocol.UDP, scanners=udp_scanner)],
            any_order=True)

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    def test_disable_periodical_scan(self, cfg):
        cfg._cfg = {'portdetection': {'scan_enabled': False}}
        self.thread._get_nodes_for_scanning = MagicMock()

        yield self.thread()
        self.assertFalse(self.thread._get_nodes_for_scanning.called)

    @patch('scans.scanner.Scanner.next_scan', 75)
    @patch('scans.scanner.Scanner.previous_scan', 57)
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_in_progress(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.push_config.return_value = Future()
        cfg.toucan.push_config.return_value.set_result(MagicMock())

        self.thread.scan_start = 17
        await self.thread.update_scan_status(ScanStatus.IN_PROGRESS)

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

    @patch('scans.scanner.Scanner.next_scan', 75)
    @patch('scans.scanner.Scanner.previous_scan', 57)
    @patch('scans.scanner.time.time', MagicMock(return_value=300))
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_idle(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.push_config.return_value = Future()
        cfg.toucan.push_config.return_value.set_result(MagicMock())

        self.thread.scan_start = 17
        await self.thread.update_scan_status(ScanStatus.IDLE)

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

    def test_shutdown_condition(self):
        self.assertEqual(self.thread.shutdown_condition, self.thread._shutdown_condition)

    @gen_test
    async def test_clean_scan(self):
        self.thread.update_scan_status = MagicMock(return_value=Future())
        self.thread.update_scan_status.return_value.set_result(True)

        self.thread._shutdown_condition = MagicMock()

        await self.thread._clean_scan()

        self.thread.update_scan_status.assert_called_once_with(ScanStatus.IDLE)
        self.thread._shutdown_condition.set.assert_called_once_with()

    @patch('scans.scanner.Scanner.previous_scan', new_callable=PropertyMock())
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_without_toucan(self, cfg, prev_scan):
        cfg.toucan = None
        await self.thread.update_scan_status(ScanStatus.IDLE)
        self.assertFalse(prev_scan.called)

    @patch('scans.scanner.MasscanPorts')
    @patch('scans.scanner.PortsScan')
    def test_tcp_scanners(self, scan, masscan):
        result = self.thread._tcp_scanners
        expected = {
            self.thread.IPV4: [masscan.return_value],
            self.thread.IPV6: [scan.return_value]
        }

        self.assertEqual(result, expected)
        scan.assert_called_once_with(ipv6=True, tcp=True, udp=False)
        masscan.assert_called_once_with(udp=False)

    @patch('scans.scanner.PortsScan')
    def test_udp_scanners(self, scan):
        result = self.thread._udp_scanners
        expected = {
            self.thread.IPV4: [scan.return_value],
            self.thread.IPV6: [scan.return_value]
        }

        self.assertEqual(result, expected)
        scan.assert_has_calls((
            call(ipv6=False, tcp=False, udp=True),
            call(ipv6=True, tcp=False, udp=True)))

    @patch('scans.scanner.Scanner._udp_scanners', new_callable=PropertyMock)
    @patch('scans.scanner.Scanner._tcp_scanners', new_callable=PropertyMock)
    def test_scanners(self, tcp_scanners, udp_scanners):
        result = self.thread.scanners

        expected = {
            TransportProtocol.UDP: udp_scanners.return_value,
            TransportProtocol.TCP: tcp_scanners.return_value
        }

        self.assertEqual(result, expected)

    @patch('scans.scanner.Scanner.scanners', new_callable=PropertyMock)
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_call_without_nodes(self, cfg, scanners):
        cfg._cfg = {'portdetection': {'scan_enabled': True}}
        nodes = []
        future = Future()
        future.set_result(nodes)
        self.thread._get_nodes_for_scanning = MagicMock(return_value=future)

        tcp_scanner = MagicMock()
        udp_scanner = MagicMock()

        scanners.return_value = {
            TransportProtocol.TCP: tcp_scanner,
            TransportProtocol.UDP: udp_scanner
        }

        future = Future()
        future.set_result(MagicMock())
        self.thread.run_scan = MagicMock(return_value=future)

        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.thread.run_scan.return_value = future_run_scan

        await self.thread()
        self.assertFalse(self.thread.run_scan.called)
