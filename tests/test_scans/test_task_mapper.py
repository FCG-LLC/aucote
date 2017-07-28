import ipaddress
from collections import OrderedDict
from unittest.mock import Mock, patch, MagicMock

from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from scans.task_mapper import TaskMapper
from structs import Port, TransportProtocol, Scan, Node
from utils import Config


class TaskMapperTest(AsyncTestCase):
    EXECUTOR_CONFIG = {
        'apps': {
            'test': {
                'class': MagicMock(),
                'async': False
            },
            'test2': {
                'class': MagicMock(),
                'async': False
            }
        },
        'node_scan': ['test']
    }

    NODE = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))

    UDP = Port(transport_protocol=TransportProtocol.UDP, number=21, node=NODE)
    UDP.service_name = 'ftp'
    UDP.scan = Scan(start=19.0)

    TCP = Port(transport_protocol=TransportProtocol.TCP, number=22, node=NODE)
    TCP.service_name = 'ssh'
    TCP.scan = Scan(start=19.0)

    def setUp(self):
        super(TaskMapperTest, self).setUp()
        self.executor = Mock()
        self.exploits = OrderedDict({
            'test': [
                Exploit(exploit_id=1, name='test_1'),
                Exploit(exploit_id=2, name='test_2')
            ]
        })

        self.exploits.update(test2=[Exploit(exploit_id=3)])
        self.executor.exploits.find_all_matching.return_value = self.exploits
        self.scan = Scan()

        self.task_mapper = TaskMapper(aucote=self.executor, scan=self.scan)

    def tearDown(self):
        self.EXECUTOR_CONFIG['apps']['test']['class'].reset_mock()
        self.EXECUTOR_CONFIG['apps']['test2']['class'].reset_mock()

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    def test_properties(self):
        self.assertEqual(self.task_mapper.exploits, self.executor.exploits)
        self.assertEqual(self.task_mapper._aucote, self.executor)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_app_running(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                },
                'test2': {
                    'enable': True,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }
        self.executor.storage.get_security_scan_info.return_value = []
        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 1)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 1)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_app_add_async(self, cfg):
        self.EXECUTOR_CONFIG['apps']['test']['async'] = True
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                },
                'test2': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }
        self.executor.storage.get_security_scan_info.return_value = []
        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)
        self.task_mapper._aucote.add_async_task.assert_called_once_with(
            self.EXECUTOR_CONFIG['apps']['test']['class'].return_value)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get', MagicMock(return_value=False))
    @gen_test
    async def test_disable_all_app_running(self):
        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 0)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 0)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_disable_first_app_running(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                },
                'test2': {
                    'enable': True,
                    'period': '0s',
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }
        self.executor.storage.get_security_scan_info.return_value = []
        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 0)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 1)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @patch('time.time', MagicMock(return_value=25.0))
    @gen_test
    async def test_storage_all_scanned_recently(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'script_networks': {},
                    'networks': [],
                    'periods': {
                        'test_1': '1d',
                        'test_2': '2d'
                    }
                },
                'test2': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }

        self.executor.storage.get_security_scan_info.return_value = [
            {
                "exploit": self.exploits['test'][0],
                "port": self.UDP,
                "scan_start": 17.0,
                "scan_end": 26.0,
                "exploit_name": "test_1"
            },
            {
                "exploit": self.exploits['test'][1],
                "port": self.UDP,
                "scan_start": 12.0,
                "scan_end": 17.0,
                "exploit_name": "test_2"
            },
        ]

        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']
        expected = []

        self.assertEqual(result, expected)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @patch('time.time', MagicMock(return_value=25.0))
    @gen_test
    async def test_storage_one_scanned_recently(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'script_networks': {},
                    'networks': [],
                    'periods': {
                        'test_1': '1d',
                        'test_2': '1s'
                    }
                },
                'test2': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }

        self.executor.storage.get_security_scan_info.return_value = [
            {
                "exploit": self.exploits['test'][0],
                "port": self.UDP,
                "scan_start": 17.0,
                "scan_end": 26.0,
                "exploit_name": "test_1"
            },
            {
                "exploit": self.exploits['test'][1],
                "port": self.UDP,
                "scan_start": 12.0,
                "scan_end": 17.0,
                "exploit_name": "test_2"
            }
        ]

        self.task_mapper.store_security_scan = MagicMock()

        expected = [self.exploits['test'][1]]
        expected_call = {
            'exploits': [self.exploits['test'][1]],
            'port': self.UDP,
            'storage': self.executor.storage
        }

        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']

        self.assertEqual(result, expected)
        self.assertCountEqual(self.task_mapper.store_security_scan.call_args[1], expected_call)

    def test_store_scan(self):
        self.UDP.scan = Scan(start=25.0)
        self.task_mapper.store_security_scan(exploits=[self.exploits['test'][0]], port=self.UDP,
                                             storage=self.executor.storage)

        result = self.executor.storage.save_security_scans.call_args[1]
        expected = {
            'exploits': [self.exploits['test'][0]],
            'port': self.UDP
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(result['port'].scan.start, self.UDP.scan.start)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_copying_port(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                    'period': '0s'
                },
                'test2': {
                    'enable': True,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                    'period': '0s'
                }
            }
        }
        self.executor.storage.get_security_scan_info.return_value = []
        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertNotEqual(id(self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['port']), id(self.UDP))
        self.assertNotEqual(id(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_args[1]['port']), id(self.TCP))

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_restricted_script_network(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'periods': {
                        'test_1': '1s',
                        'test_2': '1s',
                        'test_3': '1s',
                        'test_4': '1s'
                    },
                    'script_networks': {
                        'test_1': [
                            '0.0.0.0/32'
                        ],
                        'test_3': [
                            '0.0.0.0/32'
                        ],
                        'test_4': [
                            '0.0.0.0/32'
                        ]
                    },
                    'networks': [
                        '0.0.0.0/0'
                    ]
                },
                'test2': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }

        self.exploits = OrderedDict({
            'test': [
                Exploit(exploit_id=1, name='test_1'),
                Exploit(exploit_id=2, name='test_2'),
                Exploit(exploit_id=3, name='test_3'),
                Exploit(exploit_id=4, name='test_4')
            ]
        })
        self.executor.exploits.find_all_matching.return_value = self.exploits
        self.task_mapper._executor = self.executor

        self.executor.storage.get_security_scan_info.return_value = [
            {
                "exploit": self.exploits['test'][0],
                "port": self.UDP,
                "scan_start": 17.0,
                "scan_end": 26.0,
                "exploit_name": "test_1"
            },
            {
                "exploit": self.exploits['test'][1],
                "port": self.UDP,
                "scan_start": 12.0,
                "scan_end": 17.0,
                "exploit_name": "test_2"
            }
        ]

        self.task_mapper.store_security_scan = MagicMock()

        expected = [self.exploits['test'][1]]

        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']

        self.assertEqual(result, expected)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_restricted_app_network(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'script_networks': {},
                    'periods': {
                        'test_1': '1s',
                        'test_2': '1s'
                    },
                    'networks': [
                        '0.0.0.0/0'
                    ]
                },
                'test2': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }

        self.executor.storage.get_security_scan_info.return_value = [
            {
                "exploit": self.exploits['test'][0],
                "port": self.UDP,
                "scan_start": 17.0,
                "scan_end": 26.0,
                "exploit_name": "test_1"
            },
            {
                "exploit": self.exploits['test'][1],
                "port": self.UDP,
                "scan_start": 12.0,
                "scan_end": 17.0,
                "exploit_name": "test_2"
            }
        ]

        self.task_mapper.store_security_scan = MagicMock()
        expected = [self.exploits['test'][0], self.exploits['test'][1]]
        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)
        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']

        self.assertEqual(result, expected)

    @patch('scans.task_mapper.time.time', MagicMock(return_value=10))
    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('scans.task_mapper.cfg', new_callable=Config)
    @gen_test
    async def test_scan_after_service_change(self, cfg):
        cfg._cfg = {
            'tools': {
                'test': {
                    'enable': True,
                    'periods': {},
                    'script_networks': {},
                    'networks': [
                        '0.0.0.0/0'
                    ],
                    'period': '0s'
                },
                'test2': {
                    'enable': False,
                    'periods': {},
                    'script_networks': {},
                    'networks': [],
                }
            }
        }
        exploit = Exploit(exploit_id=3, name='test_3')
        self.executor.storage.get_security_scan_info.return_value = [
            {
                "exploit": exploit,
                "port": self.UDP,
                "scan_start": 17.0,
                "scan_end": 26.0,
                "exploit_name": "test_3"
            },
            {
                "exploit": self.exploits['test'][1],
                "port": self.UDP,
                "scan_start": 12.0,
                "scan_end": 17.0,
                "exploit_name": "test_2"
            }
        ]

        self.EXECUTOR_CONFIG['apps']['test']['class'] = MagicMock()

        await self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)
        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']
        expected = [self.exploits['test'][0]]
        self.assertEqual(result, expected)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @gen_test
    async def test_assign_task_for_node(self):
        self.task_mapper._filter_exploits = MagicMock()
        class_mock = self.EXECUTOR_CONFIG['apps']['test']['class']
        self.task_mapper._aucote.exploits.find_by_apps = MagicMock()
        mock_apps = self.task_mapper._aucote.exploits.find_by_apps
        exploit = Exploit(exploit_id=3, name='test_3')
        self.task_mapper._filter_exploits.return_value = [exploit]

        mock_apps.return_value = {
            'test': [exploit]
        }

        node = Node(1, ipaddress.ip_address('127.0.0.1'))

        await self.task_mapper.assign_tasks_for_node(node)

        class_mock.assert_called_once_with(aucote=self.task_mapper._aucote, exploits=[exploit], node=node,
                                           config=self.EXECUTOR_CONFIG['apps']['test'], scan=self.scan)
