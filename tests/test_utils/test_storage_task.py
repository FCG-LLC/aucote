from queue import Empty
from unittest import TestCase
from unittest.mock import MagicMock, patch

from utils.storage_task import StorageTask


class StorageTaskTest(TestCase):
    @patch('utils.storage_task.Queue')
    def setUp(self, mock_queue):
        self.executor = MagicMock()
        self.mock_queue = mock_queue
        self.filename = ":memory:"
        self.task = StorageTask(executor=self.executor, filename=self.filename)

    @patch('utils.storage_task.Queue')
    def test_init(self, mock_queue):
        self.assertEqual(self.task.filename, self.filename)
        self.assertEqual(self.task._queue, self.mock_queue())
        self.assertEqual(self.task.executor.storage, self.task._storage)

    def test_add_query(self):
        self.task._queue = MagicMock()
        data = MagicMock()

        self.task.add_query(data)

        self.task._queue.put.assert_called_once_with(data)

    def test_call(self):
        self.task._queue.task_done.side_effect = (None, None, Exception("TEST_FIN"))
        self.task._queue.get.side_effect = ((1,), Empty(), Empty(), (2,), [(3, ), (4, )])
        self.task._storage = MagicMock()

        self.assertRaises(Exception, self.task)
        self.assertTrue(self.task._storage.clear_scan_details.called)
        self.assertEqual(self.task._storage.cursor.execute.call_count, 4)
        self.assertEqual(self.task._storage.conn.commit.call_count, 3)
        self.assertEqual(self.task._queue.get.call_count, 5)

    def test_finish_task(self):
        self.executor.unfinished_tasks = 1
        self.executor.started = True
        self.task._queue = MagicMock()

        self.task()
        self.assertIsNone(self.executor.storage)
        self.assertFalse(self.task._queue.get.called)
