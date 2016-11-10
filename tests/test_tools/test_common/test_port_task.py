from unittest import TestCase
from unittest.mock import MagicMock

from tools.common.port_task import PortTask


class PortTaskTest(TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.port = MagicMock()
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
