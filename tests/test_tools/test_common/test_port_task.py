from unittest import TestCase
from unittest.mock import MagicMock

from structs import Port
from tools.common.port_task import PortTask


class PortTaskTest(TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.port = Port(node=MagicMock(), transport_protocol=None, number=MagicMock())
        self.exploit = MagicMock()
        self.task = PortTask(executor=self.executor, port=self.port, exploits=[self.exploit])

    def test_init(self):
        self.assertEqual(self.task._port, self.port)
        self.assertEqual(self.task.executor, self.executor)
        self.assertEqual(self.task.exploit, self.exploit)

    def test_exploit_one(self):
        self.assertEqual(self.task.exploit, self.exploit)

    def test_exploit_multiple(self):
        self.task.current_exploits = [MagicMock(), MagicMock()]
        self.assertEqual(self.task.exploit, None)

    def test_get_info(self):
        result = self.task.get_info()
        expected = {
            "port": str(self.port),
            "exploits": [self.exploit.name]
        }

        self.assertDictEqual(result, expected)

    def test_get_vulnerabilities(self):
        self.assertRaises(NotImplementedError, self.task.get_vulnerabilities, [])
