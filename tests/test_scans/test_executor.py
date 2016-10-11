import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock

from aucote import Aucote
from scans.executor import Executor
from structs import Node, Port, TransportProtocol
from utils.storage import Storage
from utils.threads import ThreadPool


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class ExecutorTest(TestCase):

    def setUp(self):
        storage = MagicMock()
        storage.connect()
        self.aucote = Aucote(exploits=None, storage=storage, kudu_queue=None)
        self.executor = Executor(aucote=self.aucote)

    def test_init(self):
        executor = Executor(aucote=self.aucote)

        self.assertEqual(executor.exploits, self.aucote.exploits)
        self.assertEqual(executor.thread_pool, self.aucote.thread_pool)

    @patch('tools.masscan.MasscanPorts.scan_ports', MagicMock(return_value=[MagicMock()]))
    @patch('scans.executor.parse_period', MagicMock(return_value=10))
    @patch('scans.executor.Executor._get_ports_for_scanning')
    def test_run_executor(self, mock_get_ports):
        self.executor._thread_pool = ThreadPool()
        port = Port(node=None, number=12, transport_protocol=TransportProtocol)
        mock_get_ports.return_value = [port]

        self.executor.add_task = MagicMock()
        self.executor.run()

        self.assertEqual(self.executor.add_task.call_count, 1)

    def test_properties(self):
        self.assertEqual(self.executor.exploits, self.executor.aucote.exploits)
        self.assertEqual(self.executor.kudu_queue, self.aucote.kudu_queue)

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