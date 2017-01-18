from queue import Empty
from unittest import TestCase
from unittest.mock import MagicMock, patch, PropertyMock

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
        self.assertFalse(self.thread_pool._finish)
        self.thread_pool.stop()

        self.assertTrue(self.thread_pool._finish)
        self.thread_1.join.called_once_with()
        self.thread_2.join.called_once_with()
        self.assertEqual(self.thread_pool._threads, [])

    def test_join(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool.join()

        self.thread_pool._queue.join.assert_called_once_with()

    @patch('utils.threads.ThreadPool.unfinished_tasks', new_callable=PropertyMock)
    def test_worker_task_empty_queue(self, mock_thread):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._finish = True
        mock_thread.side_effect=(1, 0)
        self.thread_pool._queue.get.side_effect = Empty()
        self.thread_pool._worker()

    def test_worker_task_is_not_none(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._queue.task_done.side_effect = [SystemExit()]

        self.assertRaises(SystemExit, self.thread_pool._worker)
        self.thread_pool._queue.get.assert_called_once_with(timeout=10)

    def test_worker_task_is_not_none_but_raises_exception(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._queue.get.return_value.side_effect = [Exception()]
        self.thread_pool._queue.task_done.side_effect = [SystemExit()]

        self.assertRaises(SystemExit, self.thread_pool._worker)
        self.thread_pool._queue.get.assert_called_once_with(timeout=10)

    def test_unfinished(self):
        self.assertEqual(self.thread_pool.unfinished_tasks, self.thread_pool._queue.unfinished_tasks)

    def test_add_task(self):
        task = MagicMock()
        self.thread_pool.add_task(task)

        self.assertIn(task, self.thread_pool._queue.queue)

    @patch('utils.threads.Thread')
    def test_start(self, mock_thread):
        self.thread_pool._num_threads = 10
        self.thread_pool.start()

        self.assertEqual(mock_thread.return_value.daemon, True)
        self.assertEqual(mock_thread.return_value.start.call_count, 10)
        self.assertEqual(mock_thread.call_count, 10)

        self.assertEqual(len(self.thread_pool._threads), 10)
