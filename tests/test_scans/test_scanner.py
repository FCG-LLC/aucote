import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test
from scans.scanner import Scanner
from structs import Node, Port, TransportProtocol, ScanStatus, Scan, PortDetectionChange, PortScan
from utils import Config
from utils.async_task_manager import AsyncTaskManager


class ScannerTest(AsyncTestCase):
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
        self.thread._init()
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
    async def test_run_scan_as_service(self, cfg, mock_executor, mock_netiface, physical_port):
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
                'tcp': {
                    'ports': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'udp': {
                    'ports': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'sctp': {
                    'ports': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
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

        self.thread._get_special_ports = MagicMock(return_value=[port])

        ports = [ports_ipv4[0], ports_ipv6[0], port]

        scan = Scan()

        futures = []

        for i in range(20):
            future = Future()
            future.set_result(True)
            futures.append(future)

        mock_executor.return_value.side_effect = futures

        await self.thread.run_scan(nodes=nodes, scanners=scanners, scan_only=False, protocol=MagicMock(), scan=scan)

        mock_executor.assert_has_calls((call(context=self.thread.context, nodes=nodes, ports=[port], scan_only=False,
                                             scan=scan, scanner=self.thread),
                                        call(context=self.thread.context, nodes=[], ports=[ports_ipv6[0]],
                                             scan_only=False, scan=scan, scanner=self.thread),
                                        call(context=self.thread.context, nodes=[], ports=[ports_ipv4[0]],
                                             scan_only=False, scan=scan, scanner=self.thread)), any_order=True)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scanner.Scan')
    @patch('scans.scanner.Scanner.scanners', new_callable=PropertyMock)
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_periodical_scan(self, cfg, scanners, scan):
        self.thread.PROTOCOL = TransportProtocol.UDP
        nodes = MagicMock()
        future = Future()
        future.set_result(nodes)
        self.thread._get_nodes_for_scanning = MagicMock(return_value=future)

        udp_scanner = MagicMock()

        scanners.return_value = udp_scanner

        future = Future()
        future.set_result(MagicMock())
        self.thread.run_scan = MagicMock(return_value=future)

        future_run_scan = Future()
        future_run_scan.set_result(MagicMock())
        self.thread.run_scan.return_value = future_run_scan

        await self.thread.run()
        self.thread.run_scan.assert_called_once_with(nodes, scan_only=True, protocol=TransportProtocol.UDP,
                                                     scanners=udp_scanner, scan=scan())
        self.thread._get_nodes_for_scanning.assert_called_once_with(filter_out_storage=True, scan=scan(),
                                                                    timestamp=None)

    @gen_test
    async def test_periodical_scan_with_topdis_error(self):
        self.thread._get_nodes_for_scanning = MagicMock(side_effect=ConnectionError)

        await self.thread.run()

        self.assertFalse(self.thread.storage.save_scan.called)

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

    def test_scanners(self):
        with self.assertRaises(NotImplementedError):
            self.assertIs(self.thread.scanners)

    @patch('scans.scanner.Scanner.scanners', new_callable=PropertyMock)
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_call_without_nodes(self, cfg, scanners):
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

        await self.thread.run()
        self.assertFalse(self.thread.run_scan.called)

    @patch('scans.scanner.Serializer.serialize_vulnerability_change')
    def test_diff_two_last_scans(self, serializer):
        current_scan = Scan()
        previous_scan = Scan()
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.aucote.storage.get_nodes_by_scan.return_value = [node]

        port_added = Port(node, transport_protocol=TransportProtocol.TCP, number=88)
        port_added.row_id = 17
        port_removed = Port(node, transport_protocol=TransportProtocol.TCP, number=80)
        port_removed.row_id = 18
        port_unchanged = Port(node, transport_protocol=TransportProtocol.TCP, number=22)
        port_unchanged.row_id = 19

        port_scans_current = [PortScan(port=port_unchanged, scan=current_scan),
                              PortScan(port=port_added, scan=current_scan)]
        port_scans_previous = [PortScan(port=port_unchanged, scan=previous_scan),
                               PortScan(port=port_removed, scan=previous_scan)]

        self.aucote.storage.get_scans_by_node.return_value = [current_scan, previous_scan]
        self.aucote.storage.get_ports_by_scan_and_node.side_effect = (port_scans_current, port_scans_previous)

        expected = [
            PortDetectionChange(current_finding=port_scans_current[1], previous_finding=None),
            PortDetectionChange(current_finding=None, previous_finding=port_scans_previous[1])
        ]

        self.thread.diff_with_last_scan(current_scan)

        self.aucote.storage.get_nodes_by_scan.assert_called_once_with(scan=current_scan)
        self.assertEqual(len(self.aucote.storage.save_changes.call_args_list), 1)
        result = self.aucote.storage.save_changes.call_args[0][0]
        self.assertCountEqual(result, expected)
        self.assertCountEqual([serializer.call_args_list[0][0][0], serializer.call_args_list[1][0][0]], expected)

    @patch('scans.scanner.Serializer.serialize_vulnerability_change')
    def test_diff_two_last_scans_for_first_scan(self, serializer):
        current_scan = Scan()
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.aucote.storage.get_nodes_by_scan.return_value = [node]

        port_added = Port(node, transport_protocol=TransportProtocol.TCP, number=88)
        port_added.row_id = 17
        port_unchanged = Port(node, transport_protocol=TransportProtocol.TCP, number=22)
        port_unchanged.row_id = 19

        port_scans_current = [PortScan(port=port_unchanged, scan=current_scan),
                              PortScan(port=port_added, scan=current_scan)]

        self.aucote.storage.get_scans_by_node.return_value = [current_scan]
        self.aucote.storage.get_ports_by_scan_and_node.side_effect = (port_scans_current,)
        expected = [
            PortDetectionChange(current_finding=port_scans_current[1], previous_finding=None),
            PortDetectionChange(current_finding=port_scans_current[0], previous_finding=None)
        ]

        self.thread.diff_with_last_scan(current_scan)

        self.aucote.storage.get_nodes_by_scan.assert_called_once_with(scan=current_scan)
        self.assertEqual(len(self.aucote.storage.save_changes.call_args_list), 1)
        result = self.aucote.storage.save_changes.call_args[0][0]
        self.assertCountEqual(result, expected)
        self.assertCountEqual([serializer.call_args_list[0][0][0], serializer.call_args_list[1][0][0]], expected)

    @patch('scans.scanner.PhysicalPort')
    @patch('scans.scanner.netifaces')
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_run_scan_as_service_cancelled(self, cfg, mock_executor, mock_netiface, physical_port):
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
                'tcp': {
                    'ports': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'udp': {
                    'ports': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                },
                'sctp': {
                    'ports': {
                        'include': ['0-65535'],
                        'exclude': []
                    },
                }
            }
        }
        self.thread.context.cancelled = MagicMock(return_value=True)
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

        self.thread._get_special_ports = MagicMock(return_value=[port])

        ports = [ports_ipv4[0], ports_ipv6[0], port]

        scan = Scan()

        futures = []

        for i in range(20):
            future = Future()
            future.set_result(True)
            futures.append(future)

        mock_executor.return_value.side_effect = futures

        await self.thread.run_scan(nodes=nodes, scanners=scanners, scan_only=False, protocol=MagicMock(), scan=scan)

        mock_executor.assert_called_once_with(context=self.thread.context, nodes=nodes, ports=[port], scan_only=False,
                                              scan=scan, scanner=self.thread)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)
