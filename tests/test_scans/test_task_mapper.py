import ipaddress
import unittest
from collections import OrderedDict
from unittest.mock import Mock, patch, MagicMock

from fixtures.exploits import Exploit
from scans.task_mapper import TaskMapper
from structs import Port, TransportProtocol, Scan, Node
from utils import Config


class TaskMapperTest(unittest.TestCase):
    EXECUTOR_CONFIG = {
        'apps': {
            'test': {
                'class': MagicMock()
            },
            'test2': {
                'class': MagicMock()
            }
        }
    }

    NODE = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))

    UDP = Port(transport_protocol=TransportProtocol.UDP, number=21, node=NODE)
    UDP.service_name = 'ftp'
    UDP.scan = Scan(start=19.0)

    TCP = Port(transport_protocol=TransportProtocol.TCP, number = 22, node=NODE)
    TCP.service_name = 'ssh'
    TCP.scan = Scan(start=19.0)

    def setUp(self):
        self.executor = Mock()
        self.exploits = OrderedDict({
            'test': [
                Exploit(exploit_id=1, name='test_1'),
                Exploit(exploit_id=2, name='test_2')
            ]
        })

        self.exploits.update(test2=[Exploit(exploit_id=3)])
        self.executor.exploits.find_all_matching.return_value = self.exploits
        self.task_mapper = TaskMapper(self.executor)

    def tearDown(self):
        self.EXECUTOR_CONFIG['apps']['test']['class'].reset_mock()
        self.EXECUTOR_CONFIG['apps']['test2']['class'].reset_mock()

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    def test_properties(self):
        self.assertEqual(self.task_mapper.exploits, self.executor.exploits)
        self.assertEqual(self.task_mapper.executor, self.executor)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get', MagicMock(side_effect=(True, MagicMock(), True, MagicMock())))
    def test_app_running(self):
        self.executor.storage.get_scan_info.return_value = []
        self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 1)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 1)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get', MagicMock(return_value=False))
    def test_disable_all_app_running(self):
        self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 0)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 0)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get', MagicMock(side_effect=(False, True, MagicMock())))
    def test_disable_first_app_running(self):
        self.executor.storage.get_scan_info.return_value = []
        self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 0)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 1)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get')
    @patch('time.time', MagicMock(return_value=25.0))
    def test_storage_all_scanned_recently(self, mock_cfg):
        mock_cfg.side_effect = (True, Config({'test_1': '1d', 'test_2': '2d'}), False)

        self.executor.storage.get_scan_info.return_value = [
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

        self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']
        expected = []

        self.assertEqual(result, expected)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get')
    @patch('time.time', MagicMock(return_value=25.0))
    def test_storage_one_scanned_recently(self, mock_cfg):
        mock_cfg.side_effect = (True, Config({'test_1': '1d', 'test_2': '1s'}), False)

        self.executor.storage.get_scan_info.return_value = [
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

        self.task_mapper.store_scan_details = MagicMock()

        expected = [self.exploits['test'][1]]
        expected_call = {
            'exploits': [self.exploits['test'][1]],
            'port': self.UDP,
            'storage': self.executor.storage
        }

        self.task_mapper.assign_tasks(self.UDP, storage=self.executor.storage)

        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']

        self.assertEqual(result, expected)
        self.assertCountEqual(self.task_mapper.store_scan_details.call_args[1], expected_call)

    def test_store_scan(self):
        self.UDP.scan = Scan(start=25.0)
        self.task_mapper.store_scan_details(exploits=[self.exploits['test'][0]], port=self.UDP,
                                            storage=self.executor.storage)

        result = self.executor.storage.save_scans.call_args[1]
        expected = {
            'exploits': [self.exploits['test'][0]],
            'port': self.UDP
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(result['port'].scan.start, self.UDP.scan.start)

    @patch('aucote_cfg.cfg.get', MagicMock(side_effect=(True, KeyError, False)))
    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    def test_assign_tasks_config_exception(self):
        self.executor.storage.get_scan_info = MagicMock(return_value=[])
        self.task_mapper.assign_tasks(port=self.UDP, storage=self.executor.storage)

        result = self.EXECUTOR_CONFIG['apps']['test']['class'].call_args[1]['exploits']
        expected = self.exploits['test']

        self.assertEqual(result, expected)
