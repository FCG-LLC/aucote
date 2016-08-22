import unittest
from unittest.mock import Mock, patch, MagicMock

from fixtures.exploits import Exploit
from scans.task_mapper import TaskMapper
from structs import Port, TransportProtocol

EXECUTOR_CONFIG = {
    'apps': {
        'test': {
            'class': MagicMock()
        },
        'test2':{
            'class': MagicMock()
        }
    }
}


@patch("scans.task_mapper.EXECUTOR_CONFIG", EXECUTOR_CONFIG)
class TaskMapperTest(unittest.TestCase):

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
        self.executor.exploits.find_all.return_value = {
            'test': [
                Exploit()
            ],
            'test2': [
                Exploit()
            ]
        }
        self.task_mapper = TaskMapper(self.executor)

    def test_properties(self):
        self.assertEqual(self.task_mapper.exploits, self.executor.exploits)

    def test_app_running(self):
        self.task_mapper.assign_tasks(self.UDP)
        self.assertEqual(EXECUTOR_CONFIG['apps']['test']['class'].call_count, 1)