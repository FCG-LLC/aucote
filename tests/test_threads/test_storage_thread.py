from queue import Empty
from unittest import TestCase
from unittest.mock import MagicMock, patch

from structs import StorageQuery
from threads.storage_thread import StorageThread


class StorageThreadTest(TestCase):
    @patch('threads.storage_thread.Queue')
    def setUp(self, mock_queue):
        self.mock_queue = mock_queue
        self.filename = ":memory:"
        self.task = StorageThread(filename=self.filename)

    @patch('threads.storage_thread.Queue')
    def test_init(self, mock_queue):
        self.assertEqual(self.task.filename, self.filename)
        self.assertEqual(self.task._queue, self.mock_queue())

    def test_add_query(self):
        self.task._queue = MagicMock()
        data = MagicMock()

        self.task.add_query(data)

        self.task._queue.put.assert_called_once_with(data)

    def test_call(self):
        self.task._queue.task_done.side_effect = (None, None, Exception("TEST_FIN"))
        self.task._queue.get.side_effect = ((1,), Empty(), Empty(), (2,), [(3, ), (4, )])
        self.task._storage = MagicMock()

        self.assertRaises(Exception, self.task.run)
        self.assertTrue(self.task._storage.clear_scan_details.called)
        self.assertEqual(self.task._storage.cursor.execute.call_count, 4)
        self.assertEqual(self.task._storage.conn.commit.call_count, 3)
        self.assertEqual(self.task._queue.get.call_count, 5)

    def test_finish_task(self):
        self.task.finish = True
        self.task._queue = MagicMock()

        self.task.run()
        self.assertFalse(self.task._queue.get.called)

    def test_stop(self):
        self.assertFalse(self.task.finish)
        self.task.stop()
        self.assertTrue(self.task.finish)

    def test_storage_getter(self):
        self.assertEqual(self.task.storage, self.task._storage)

    def test_storage_query_proceed(self):
        self.task._queue.task_done.side_effect = (None, Exception("TEST_FIN"))
        query = StorageQuery("test_query")
        query.lock = MagicMock()
        self.task._queue.get.side_effect = (query, StorageQuery(None))
        self.task._storage = MagicMock()
        result = MagicMock()
        self.task._storage.cursor.execute.side_effect = (result, Exception("TEST_EXCEPTION"))

        self.assertRaises(Exception, self.task.run)
        self.assertEqual(self.task._storage.cursor.execute.call_count, 2)
        query.lock.release.assert_called_once_with()
        self.assertEqual(query.result, result.fetchall.return_value)

    def test_get_info(self):
        result = self.task.get_info()
        expected = {
            'path': self.filename
        }

        self.assertDictEqual(result, expected)