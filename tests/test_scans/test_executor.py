import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from aucote import Aucote
from scans import Executor
from structs import Node, Port, TransportProtocol
from utils.exceptions import TopdisConnectionException
from utils.storage import Storage
from utils.threads import ThreadPool


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class ExecutorTest(TestCase):

    @patch('scans.executor.ScanTask._get_nodes', MagicMock(return_value=[]))
    @patch('scans.executor.Executor._get_nodes_for_scanning', MagicMock(return_value=[]))
    def setUp(self):
        storage = Storage(":memory:")
        storage.connect()
        self.aucote = Aucote(exploits=None, storage=storage, kudu_queue=None)
        self.executor = Executor(aucote=self.aucote)

    @patch('scans.executor.ScanTask._get_nodes')
    def test_init(self, mock_get_nodes):
        return_value = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        mock_get_nodes.return_value=return_value
        executor = Executor(aucote=self.aucote)

        mock_get_nodes.assert_called_once_with()
        self.assertEqual(executor.nodes, return_value)
        self.assertEqual(executor.exploits, self.aucote.exploits)
        self.assertEqual(executor.thread_pool, self.aucote.thread_pool)

    @patch('tools.masscan.MasscanPorts.scan_ports', MagicMock(return_value=[MagicMock()]))
    @patch('scans.executor.parse_period', MagicMock(return_value=10))
    @patch('scans.executor.Storage')
    def test_run_executor(self, mock_storage):
        self.executor._thread_pool = ThreadPool()

        self.executor._get_nodes = MagicMock()
        self.executor.add_task = MagicMock()
        self.executor.run()

        self.assertEqual(self.executor.add_task.call_count, 1)

    def test_properties(self):
        self.assertEqual(self.executor.exploits, self.executor.aucote.exploits)
        self.assertEqual(self.executor.kudu_queue, self.aucote.kudu_queue)

    @patch('scans.executor.ScanTask._get_nodes')
    def test_get_nodes_for_scanning(self, mock_get_nodes):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)

        nodes = [node_1, node_2,]

        mock_get_nodes.return_value=nodes

        self.executor.storage.get_nodes = MagicMock(return_value=[node_2, node_3])

        result = self.executor._get_nodes_for_scanning()
        expected = [node_1]

        self.assertListEqual(result, expected)

    def test_get_ports_for_scanning(self):
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)

        port_1 = Port(node=node_1, number=80, transport_protocol=TransportProtocol.TCP)
        port_2 = Port(node=node_2, number=80, transport_protocol=TransportProtocol.TCP)
        port_3 = Port(node=node_3, number=80, transport_protocol=TransportProtocol.TCP)

        ports = [port_1, port_2]

        result = self.executor._get_ports_for_scanning(ports, [port_2, port_3])
        expected = [port_1]

        self.assertListEqual(result, expected)

    def test_add_task(self):
        self.executor._thread_pool = MagicMock()
        data = MagicMock()

        self.executor.add_task(data)
        self.executor._thread_pool.add_task.called_once_with(data)

    def test_call_method(self):
        self.executor.run = MagicMock()
        self.executor()

        self.executor.run.assert_called_once_with()