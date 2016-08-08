import unittest
from unittest.mock import Mock, patch, MagicMock

from scans.task_mapper import TaskMapper
from structs import Port, TransportProtocol


Script1 = MagicMock()
Script2 = MagicMock()
Script3 = MagicMock()
Script4 = MagicMock()

SERVICE_TO_SCRIPTS = {
    'ftp': [Script1, Script3],
    'ssh': [Script2, Script4],
}

PORT_TO_SCRIPTS = {
    "TCP": {
        22: [Script1, Script2],
    },
    "UDP": {
        21: [Script3, Script4]
    }
}


@patch("scans.task_mapper.SERVICE_TO_SCRIPTS", SERVICE_TO_SCRIPTS)
@patch("scans.task_mapper.PORT_TO_SCRIPTS", PORT_TO_SCRIPTS)
class TaskMapperTest(unittest.TestCase):

    UDP = Port()
    UDP.transport_protocol = TransportProtocol.from_nmap_name("UDP")
    UDP.number = 21
    UDP.service_name = 'ftp'

    TCP = Port()
    TCP.transport_protocol = TransportProtocol.from_nmap_name("TCP")
    TCP.number = 22
    TCP.service_name = 'ssh'

    def setUp(self):
        self.executor = Mock()
        self.task_mapper = TaskMapper(self.executor)

    def test_services(self):
        self.executor.add_task = Mock(side_effect=self.udp_port)
        self.task_mapper.assign_tasks(self.UDP)
        self.executor.add_task = Mock(side_effect=self.tcp_port)
        self.task_mapper.assign_tasks(self.TCP)

    def udp_port(self, task):
        self.assertEqual(task._port, self.UDP)
        self.assertIn(Script1, task._script_classes)
        self.assertIn(Script3, task._script_classes)
        self.assertIn(Script4, task._script_classes)
        self.assertNotIn(Script2, task._script_classes)

    def tcp_port(self, task):
        self.assertEqual(task._port, self.TCP)
        self.assertIn(Script1, task._script_classes)
        self.assertIn(Script2, task._script_classes)
        self.assertIn(Script4, task._script_classes)
        self.assertNotIn(Script3, task._script_classes)



