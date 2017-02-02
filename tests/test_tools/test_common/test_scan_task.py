from unittest import TestCase
from unittest.mock import MagicMock

from tools.common.scan_task import ScanTask


class ScanTaskTest(TestCase):
    
    def setUp(self):
        self.command = MagicMock()
        self.task = ScanTask(self.command)
    
    def test_prepare_args(self):
        self.assertRaises(NotImplementedError, self.task.prepare_args, [])
