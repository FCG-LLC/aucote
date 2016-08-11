from unittest import TestCase
from unittest.mock import MagicMock

from scans import Executor
from utils.task import Task


class TaskTest(TestCase):
    """
    Testing task behaviour
    """

    def setUp(self):
        """
        Set up init variables
        """
        self.executor = MagicMock()
        self.executor.kudu_queue = MagicMock()
        self.executor.exploits = MagicMock()

        self.task = Task(executor=self.executor)

    def test_init(self):
        """
        Test init and properties
        """
        self.assertEqual(self.task.executor, self.executor)
        self.assertEqual(self.task.kudu_queue, self.executor.kudu_queue)
        self.assertEqual(self.task.exploits, self.executor.exploits)

    def test_call(self):
        """
        Test call
        """
        self.assertRaises(NotImplementedError, self.task)