import unittest
from collections import OrderedDict
from unittest.mock import Mock, patch, MagicMock

from fixtures.exploits import Exploit
from scans.task_mapper import TaskMapper
from structs import Port, TransportProtocol


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

    UDP = Port()
    UDP.transport_protocol = TransportProtocol.UDP
    UDP.number = 21
    UDP.service_name = 'ftp'

    TCP = Port()
    TCP.transport_protocol = TransportProtocol.TCP
    TCP.number = 22
    TCP.service_name = 'ssh'

    def setUp(self):
        self.executor = Mock()
        self.exploits = OrderedDict({
            'test': [
                Exploit(),
                Exploit()
            ]
        })
        self.exploits.update(test2=Exploit())
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
    @patch('aucote_cfg.cfg.get', MagicMock(return_value=True))
    def test_app_running(self):
        self.task_mapper.assign_tasks(self.UDP)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 1)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 1)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get', MagicMock(return_value=False))
    def test_disable_all_app_running(self):
        self.task_mapper.assign_tasks(self.UDP)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 0)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 0)

    @patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
    @patch('aucote_cfg.cfg.get', MagicMock(side_effect=(False, True)))
    def test_disable_first_app_running(self):
        self.task_mapper.assign_tasks(self.UDP)

        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test']['class'].call_count, 0)
        self.assertEqual(self.EXECUTOR_CONFIG['apps']['test2']['class'].call_count, 1)
