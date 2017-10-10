import ipaddress
from unittest.mock import patch, MagicMock, PropertyMock, call

import time
from tornado.httpclient import HTTPError

from cpe import CPE
from croniter import croniter
from netaddr import IPSet
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from fixtures.exploits import Exploit
from scans.scan_async_task import ScanAsyncTask
from structs import Node, PhysicalPort, Scan, Port, TransportProtocol, ScanStatus, CPEType, VulnerabilityChange, \
    VulnerabilityChangeType, PortDetectionChange
from utils import Config
from utils.async_task_manager import AsyncTaskManager


class ScanAsyncTaskTest(AsyncTestCase):
    @patch('scans.scan_async_task.croniter', MagicMock(return_value=croniter('* * * * *', time.time())))
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def setUp(self, cfg):
        super(ScanAsyncTaskTest, self).setUp()
        self.cfg = {
            'portdetection': {
                'test_name': {
                    'scan_type': 'LIVE',
                    'live_scan': {
                        'min_time_gap': 0,
                    },
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

        self.thread = ScanAsyncTask(aucote=self.aucote)
        self.thread.NAME = 'test_name'
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

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.parse_period', MagicMock(return_value=5))
    @gen_test
    async def test_get_nodes_for_scanning(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.networks.include'] = ['127.0.0.2/31']

        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)
        node_4 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)  # This same like node_3 for testing uniqueness

        nodes = [node_1, node_2, node_3, node_4]
        future = Future()
        future.set_result(nodes)
        self.aucote.topdis.get_nodes.return_value = future

        self.thread.storage.get_nodes = MagicMock(return_value=[node_2])

        scan = Scan()

        result = await self.thread._get_nodes_for_scanning(scan)
        expected = [node_3]

        self.assertListEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_get_networks_list(self, cfg):
        cfg._cfg = {
            'portdetection': {
                'test_name': {
                    'networks': {
                        'include': [
                            '127.0.0.1/24',
                            '128.0.0.1/13'
                        ]
                    }
                }
            }
        }
        result = self.thread._get_networks_list()
        expected = IPSet(['127.0.0.1/24', '128.0.0.1/13'])

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg.get', MagicMock(side_effect=KeyError("test")))
    def test_get_networks_list_no_cfg(self):

        self.assertRaises(SystemExit, self.thread._get_networks_list)

    def test_current_scan_getter(self):
        expected = [MagicMock(), MagicMock()]
        self.thread._current_scan = expected
        result = self.thread.current_scan

        self.assertCountEqual(result, expected)
        self.assertNotEqual(id(result), id(expected))

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_previous_scan(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.scan_type'] = 'PERIODIC'
        cfg['portdetection.test_name.periodic_scan.cron'] = '* * * * *'

        expected = 480
        result = self.thread.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_previous_scan_second_test(self, cfg):
        cfg._cfg = self.cfg
        cfg['portdetection.test_name.scan_type'] = 'PERIODIC'
        cfg['portdetection.test_name.periodic_scan.cron'] = '*/12 * * * *'

        expected = 0
        result = self.thread.previous_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=595))
    def test_next_scan(self, cfg):
        cfg._cfg = self.cfg

        expected = 600
        result = self.thread.next_scan

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron(self, cfg):
        expected = "* * * * */45"
        cfg['portdetection.test_name.scan_type'] = "PERIODIC"
        cfg['portdetection.test_name.periodic_scan.cron'] = expected
        result = self.thread._scan_cron()
        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_interval_periodic(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "PERIODIC"

        result = self.thread._scan_interval()
        expected = 0

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_interval_live(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "LIVE"
        cfg['portdetection.test_name.live_scan.min_time_gap'] = "5m13s"

        result = self.thread._scan_interval()
        expected = 313

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron_periodic(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "PERIODIC"
        cfg['portdetection.test_name.periodic_scan.cron'] = "*/2 3 */5 * *"

        result = self.thread._scan_cron()
        expected = "*/2 3 */5 * *"

        self.assertEqual(result, expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_scan_cron_live(self, cfg):
        cfg['portdetection.test_name.scan_type'] = "LIVE"

        result = self.thread._scan_cron()
        expected = '* * * * *'

        self.assertEqual(result, expected)

    @gen_test
    async def test_run(self):
        with self.assertRaises(NotImplementedError):
            await self.thread.run()

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_call(self, cfg):
        self.thread.NAME = 'test_name'
        cfg['portdetection.test_name.scan_enabled'] = True
        self.thread.run = MagicMock(return_value=Future())
        self.thread.run.return_value.set_result(True)

        await self.thread()

        self.thread.run.assert_called_once_with()

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_call_disabled(self, cfg):
        self.thread.NAME = 'test_name'
        cfg['portdetection.test_name.scan_enabled'] = False
        self.thread.run = MagicMock()

        await self.thread()

        self.assertFalse(self.thread.run.called)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_is_exploit_allowed_allowed(self, cfg):
        self.thread.NAME = 'test_name'
        cfg['portdetection.test_name.scripts'] = [1]

        exploit = Exploit(exploit_id=1)
        self.assertTrue(self.thread.is_exploit_allowed(exploit))

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_is_exploit_allowed_allowed_string(self, cfg):
        self.thread.NAME = 'test_name'
        cfg['portdetection.test_name.scripts'] = ["1"]

        exploit = Exploit(exploit_id=1)
        self.assertTrue(self.thread.is_exploit_allowed(exploit))

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    def test_is_exploit_allowed_not_allowed(self, cfg):
        self.thread.NAME = 'test_name'
        cfg['portdetection.test_name.scripts'] = []

        exploit = Exploit(exploit_id=1)
        self.assertFalse(self.thread.is_exploit_allowed(exploit))

    @patch('scans.scan_async_task.ScanAsyncTask.next_scan', 75)
    @patch('scans.scan_async_task.ScanAsyncTask.previous_scan', 57)
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_in_progress(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.push_config.return_value = Future()
        cfg.toucan.push_config.return_value.set_result(MagicMock())

        cfg.toucan.get.return_value = Future()
        cfg.toucan.get.return_value.set_result({'portdetection.test_name.status.scan_start': 23,
                                                'portdetection.test_name.status.next_scan_start': 23,
                                                'portdetection.test_name.status.code': 'IDLE',
                                                'portdetection.test_name.scan_type': 'PERIODIC'})

        self.thread.scan_start = 17
        self.thread.NAME = 'test_name'
        await self.thread.update_scan_status(ScanStatus.IN_PROGRESS)

        expected = {
            'portdetection': {
                'test_name': {
                    'status': {
                        'previous_scan_start': 23,
                        'next_scan_start': 75,
                        'scan_start': 17,
                        'code': "IN PROGRESS"
                    }
                }
            }
        }

        cfg.toucan.push_config.assert_called_once_with(expected, overwrite=True, keep_history=False)

    @patch('scans.scan_async_task.ScanAsyncTask.next_scan', 75)
    @patch('scans.scan_async_task.ScanAsyncTask.previous_scan', 57)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=300))
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @gen_test
    async def test_update_scan_status_to_idle(self, cfg):
        cfg.toucan = MagicMock()
        cfg.toucan.push_config.return_value = Future()
        cfg.toucan.push_config.return_value.set_result(MagicMock())

        cfg.toucan.get.return_value = Future()
        cfg.toucan.get.return_value.set_result({'portdetection.test_name.status.scan_start': 23,
                                                'portdetection.test_name.status.next_scan_start': 23,
                                                'portdetection.test_name.status.code': 23,
                                                'portdetection.test_name.scan_type': 'PERIODIC'})

        self.thread.scan_start = 17
        self.thread.NAME = 'test_name'
        await self.thread.update_scan_status(ScanStatus.IDLE)

        expected = {
            'portdetection': {
                'test_name': {
                    'status': {
                        'previous_scan_start': 23,
                        'next_scan_start': 75,
                        'scan_start': 17,
                        'previous_scan_duration': 283,
                        'code': "IDLE"
                    }
                }
            }
        }

        cfg.toucan.push_config.assert_called_once_with(expected, overwrite=True, keep_history=False)
