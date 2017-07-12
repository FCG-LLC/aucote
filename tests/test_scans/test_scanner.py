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

    @patch('scans.scanner.netifaces')
    @patch('scans.scanner.PortsScan')
    @patch('scans.scanner.MasscanPorts')
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
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
                '_internal': {
                    'nmap_udp': False
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

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports, scan_only=False, nodes=[node_1])
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scanner.netifaces')
    @patch('scans.scanner.PortsScan')
    @patch('scans.scanner.MasscanPorts')
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
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
                '_internal': {
                    'nmap_udp': False
                }
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
                                              nodes=[node_1], scan_only=False)
        self.thread.aucote.async_task_manager.stop.assert_called_once_with()

    @patch('scans.scanner.netifaces')
    @patch('scans.scanner.PortsScan')
    @patch('scans.scanner.MasscanPorts')
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
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
                '_internal': {
                    'nmap_udp': False
                }
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

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports, nodes=[node_1], scan_only=scan_only)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scanner.netifaces')
    @patch('scans.scanner.PortsScan')
    @patch('scans.scanner.MasscanPorts')
    @patch('scans.scanner.Executor')
    @patch('scans.scanner.cfg', new_callable=Config)
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
                '_internal': {
                    'nmap_udp': True
                }
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

        mock_executor.assert_called_once_with(aucote=self.thread.aucote, ports=ports, nodes=[node_1], scan_only=scan_only)
        self.thread.aucote.add_task.called_once_with(mock_executor.return_value)

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_without_nodes(self, cfg):
        cfg._cfg = {
            'portdetection': {
                '_internal': {
                    'nmap_udp': False
                }
            }
        }
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    def test_run_scan_as_non_service_without_nodes(self, cfg):
        cfg._cfg = {
            'portdetection': {
                '_internal': {
                    'nmap_udp': False
                }
            }
        }
        self.thread.as_service = False
        self.thread._get_nodes_for_scanning = MagicMock(return_value=[])
        self.thread._get_networks_list = MagicMock()
        self.thread._get_networks_list.return_value = ['0.0.0.0/0']
        yield self.thread.run_scan(self.thread._get_nodes_for_scanning())
        self.assertFalse(self.thread.storage.save_nodes.called)
        self.thread.aucote.async_task_manager.stop.assert_called_once_with()

    @patch('scans.scanner.cfg', new_callable=Config)
    @gen_test
    async def test_periodical_scan(self, cfg):
        cfg._cfg = {'portdetection': {'scan_enabled': True}}
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

        await self.thread()

        self.thread._get_nodes_for_scanning.assert_called_once_with(filter_out_storage=True, timestamp=None, protocol=TransportProtocol.TCP)
        self.thread.run_scan.assert_called_once_with(nodes, scan_only=True)

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
