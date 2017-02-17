import ipaddress
from queue import Empty
from unittest import TestCase
from unittest.mock import MagicMock, patch
from structs import StorageQuery, TransportProtocol
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
        query.semaphore = MagicMock()
        self.task._queue.get.side_effect = (query, StorageQuery(None))
        self.task._storage = MagicMock()
        result = MagicMock()
        self.task._storage.cursor.execute.side_effect = (result, Exception("TEST_EXCEPTION"))

        self.assertRaises(Exception, self.task.run)
        self.assertEqual(self.task._storage.cursor.execute.call_count, 2)
        query.semaphore.release.assert_called_once_with()
        self.assertEqual(query.result, result.fetchall.return_value)

    def test_save_ports(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        ports = MagicMock()
        self.task.save_ports(ports)
        self.task._storage.save_ports.assert_called_once_with(ports)
        self.task.add_query.assert_called_once_with(self.task._storage.save_ports.return_value)

    def test_save_node(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        node = MagicMock()
        self.task.save_node(node)
        self.task._storage.save_node.assert_called_once_with(node)
        self.task.add_query.assert_called_once_with(self.task._storage.save_node.return_value)

    def test_save_nodes(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        nodes = MagicMock()
        self.task.save_nodes(nodes)
        self.task._storage.save_nodes.assert_called_once_with(nodes)
        self.task.add_query.assert_called_once_with(self.task._storage.save_nodes.return_value)

    def test_save_scan(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        exploit = MagicMock()
        port = MagicMock()
        self.task.save_scan(exploit, port)
        self.task._storage.save_scan.assert_called_once_with(exploit, port)
        self.task.add_query.assert_called_once_with(self.task._storage.save_scan.return_value)

    def test_save_scans(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        exploits = MagicMock()
        port = MagicMock()
        self.task.save_scans(exploits, port)
        self.task._storage.save_scans.assert_called_once_with(exploits, port)
        self.task.add_query.assert_called_once_with(self.task._storage.save_scans.return_value)

    def test_clear_scan_details(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        self.task.clear_scan_details()
        self.task._storage.clear_scan_details.assert_called_once_with()
        self.task.add_query.assert_called_once_with(self.task._storage.clear_scan_details.return_value)

    def test_create_tables(self):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        self.task.create_tables()
        self.task._storage.create_tables.assert_called_once_with()
        self.task.add_query.assert_called_once_with(self.task._storage.create_tables.return_value)

    @patch('threads.storage_thread.StorageQuery')
    def test_get_ports(self, mock_query):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        self.task.add_query.return_value = MagicMock(result=(
            (1, '127.0.0.1', 20, 6),
            (2, '::1', 23, 17),
        ))

        result = self.task.get_ports(100)

        self.task.add_query.return_value.semaphore.acquire.assert_called_once_with()
        self.task.add_query.assert_called_once_with(mock_query.return_value)
        mock_query.assert_called_once_with(*self.task._storage.get_ports.return_value)
        self.task._storage.get_ports.assert_called_once_with(100)

        self.assertEqual(result[0].node.id, 1)
        self.assertEqual(result[1].node.id, 2)

        self.assertEqual(result[0].node.ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].node.ip, ipaddress.ip_address('::1'))

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)

    @patch('threads.storage_thread.time.time', MagicMock(return_value=300))
    @patch('threads.storage_thread.StorageQuery')
    def test_get_ports_by_node_pasttime(self, mock_query):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        self.task.add_query.return_value = MagicMock(result=(
            (1, '127.0.0.1', 20, 6),
            (2, '::1', 23, 17),
        ))

        node = MagicMock()
        result = self.task.get_ports_by_node(node, 100)

        self.task.add_query.return_value.semaphore.acquire.assert_called_once_with()
        self.task.add_query.assert_called_once_with(mock_query.return_value)
        mock_query.assert_called_once_with(*self.task._storage.get_ports.return_value)
        self.task._storage.get_ports_by_node.assert_called_once_with(node, 200)

        self.assertEqual(result[0].node, node)
        self.assertEqual(result[1].node, node)

        self.assertEqual(result[0].number, 20)
        self.assertEqual(result[1].number, 23)

        self.assertEqual(result[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1].transport_protocol, TransportProtocol.UDP)

    @patch('threads.storage_thread.StorageQuery')
    def test_get_nodes(self, mock_query):
        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        self.task.add_query.return_value = MagicMock(result=(
            (1, '127.0.0.1'),
            (2, '::1'),
        ))

        result = self.task.get_nodes(100)

        self.task.add_query.return_value.semaphore.acquire.assert_called_once_with()
        self.task.add_query.assert_called_once_with(mock_query.return_value)
        mock_query.assert_called_once_with(*self.task._storage.get_nodes.return_value)
        self.task._storage.get_nodes.assert_called_once_with(100, None)

        self.assertEqual(result[0].id, 1)
        self.assertEqual(result[1].id, 2)

        self.assertEqual(result[0].ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1].ip, ipaddress.ip_address('::1'))

    @patch('threads.storage_thread.StorageQuery')
    def test_get_scan_info(self, mock_query):
        port = MagicMock()
        app = MagicMock()

        self.task._storage = MagicMock()
        self.task.add_query = MagicMock()
        self.task.add_query.return_value = MagicMock(result=(
            (11, None, 'test_name', 1, '127.0.0.1', 6, 11, 10., 10.),
            (22, None, 'test_name_2', 2, '::1', 17, 22, None, None),
        ))

        result = self.task.get_scan_info(port, app)

        self.task.add_query.return_value.semaphore.acquire.assert_called_once_with()
        self.task.add_query.assert_called_once_with(mock_query.return_value)
        mock_query.assert_called_once_with(*self.task._storage.get_scan_info.return_value)
        self.task._storage.get_scan_info.assert_called_once_with(port, app)

        self.assertEqual(result[0]['port'].node.id, 1)
        self.assertEqual(result[1]['port'].node.id, 2)

        self.assertEqual(result[0]['port'].node.ip, ipaddress.ip_address('127.0.0.1'))
        self.assertEqual(result[1]['port'].node.ip, ipaddress.ip_address('::1'))

        self.assertEqual(result[0]['port'].number, 11)
        self.assertEqual(result[1]['port'].number, 22)

        self.assertEqual(result[0]['port'].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(result[1]['port'].transport_protocol, TransportProtocol.UDP)

        self.assertEqual(result[0]['exploit_name'], 'test_name')
        self.assertEqual(result[1]['exploit_name'], 'test_name_2')

        self.assertEqual(result[0]['scan_start'], 10.)
        self.assertEqual(result[1]['scan_start'], 0.)

        self.assertEqual(result[0]['scan_end'], 10.)
        self.assertEqual(result[1]['scan_end'], 0.)

        self.assertEqual(result[0]['exploit'].id, 11)
        self.assertEqual(result[1]['exploit'].id, 22)

