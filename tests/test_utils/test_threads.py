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
        self.thread_pool._threads = [MagicMock()]
        self.thread_pool._queue.get.return_value = None

        self.assertIsNone(self.thread_pool._worker(0))

    def test_worker_task_is_not_none(self):
        self.thread_pool._queue = MagicMock()
        self.thread_pool._threads = [MagicMock()]
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

    def test_unfinished(self):
        self.assertEqual(self.thread_pool.unfinished_tasks, self.thread_pool._queue.unfinished_tasks)

    def test_add_task(self):
        task = MagicMock()
        self.thread_pool.add_task(task)

        self.assertIn(task, self.thread_pool._queue.queue)

    def test_stats(self):
        thread1 = MagicMock()
        thread2 = MagicMock()
        thread3 = MagicMock(task=None)

        thread4 = MagicMock()

        self.thread_pool._threads = [thread1, thread2, thread3]
        self.thread_pool._queue.queue = [thread4]
        self.thread_pool._num_threads = 123

        expected = {
            'queue': [
                self.thread_pool.get_task_info(thread4)
            ],
            'threads': [
                self.thread_pool.get_thread_info(thread1),
                self.thread_pool.get_thread_info(thread2),
            ],
            'queue_length': 1,
            'threads_length': 2,
            'threads_limit': 123
        }

        result = self.thread_pool.stats

        self.assertEqual(thread1.task.get_info.call_count, 2)
        self.assertEqual(thread2.task.get_info.call_count, 2)
        self.assertEqual(thread4.get_info.call_count, 2)

        self.assertDictEqual(result, expected)

    @patch('utils.threads.time.time', MagicMock(return_value=300))
    def test_get_thread_info(self):
        thread = MagicMock()
        thread.start_time = 100

        result = self.thread_pool.get_thread_info(thread)
        expected = self.thread_pool.get_task_info(thread.task)
        expected['start_time'] = 100
        expected['duration'] = 200

        self.assertEqual(result, expected)

    def test_get_task_info(self):
        task = MagicMock()

        result = self.thread_pool.get_task_info(task)
        expected = {
            'type': 'MagicMock',
            'data': task.get_info.return_value
        }

        self.assertDictEqual(result, expected)

    @patch('utils.threads.Thread')
    def test_start(self, mock_thread):
        self.thread_pool._num_threads = 10
        self.thread_pool.start()

        self.assertEqual(mock_thread.return_value.daemon, True)
        self.assertEqual(mock_thread.return_value.start.call_count, 10)
        self.assertEqual(mock_thread.call_count, 10)

        self.assertEqual(len(self.thread_pool._threads), 10)
