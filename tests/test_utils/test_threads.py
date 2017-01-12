from unittest import TestCase
from unittest.mock import MagicMock, patch

from utils.threads import ThreadPool


class ThreadPoolTest(TestCase):

    def setUp(self):
        self.thread_pool = ThreadPool()

        self.thread_1 = MagicMock()
        self.thread_2 = MagicMock()

        self.threads = [self.thread_1, self.thread_2]

        self.task = MagicMock()

    def test_stop(self):
        self.thread_pool._threads = self.threads
        self.thread_pool._queue = MagicMock()
        self.thread_pool.stop()

        self.assertEqual(self.thread_pool._queue.put.call_count, 2)
        self.thread_1.join.called_once_with()
        self.thread_2.join.called_once_with()
        self.assertEqual(self.thread_pool._threads, [])

    def test_join(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool.join()

        self.thread_pool._queue.join.assert_called_once_with()

    def test_worker_task_is_none(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._threads = self.threads
        self.thread_pool._queue.get.return_value = None

        self.assertIsNone(self.thread_pool._worker(0))

    def test_worker_task_is_not_none(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._threads = self.threads
        self.thread_pool._queue.task_done.side_effect = [SystemExit()]

        self.assertRaises(SystemExit, self.thread_pool._worker, 0)
        self.thread_pool._queue.get.assert_called_once_with()

    def test_worker_task_is_not_none_but_raises_exception(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._threads = self.threads
        self.thread_pool._queue.get.return_value.side_effect = [Exception()]
        self.thread_pool._queue.task_done.side_effect = [SystemExit()]

        self.assertRaises(SystemExit, self.thread_pool._worker, 0)
        self.thread_pool._queue.get.assert_called_once_with()
