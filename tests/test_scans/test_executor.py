import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock, call

from scans.executor import Executor
from structs import Node, Port, TransportProtocol, BroadcastPort
from utils import Config
from utils.threads import ThreadPool


class ExecutorTest(TestCase):

    @patch('scans.executor.cfg', new_callable=Config)
    def setUp(self, cfg):
        cfg._cfg = {
            'service': {
                'scans': {
                    'broadcast': True,
                    'port_period': None
                }
            }
        }
        self.cfg = cfg
        self.aucote = MagicMock()
        self.aucote.storage = MagicMock()
        self.executor = Executor(aucote=self.aucote)

    def test_init(self):
        self.assertEqual(self.executor.exploits, self.aucote.exploits)
        self.assertEqual(self.executor.thread_pool, self.aucote.thread_pool)
        self.assertEqual(self.executor.ports, [BroadcastPort()])

    @patch('tools.masscan.MasscanPorts.scan_ports', MagicMock(return_value=[MagicMock()]))
    @patch('scans.executor.parse_period', MagicMock(return_value=10))
    @patch('scans.executor.Executor._get_ports_for_scanning')
    @patch('scans.executor.cfg', new_callable=Config)
    def test_run_executor(self, cfg, mock_get_ports):
        cfg._cfg = self.cfg._cfg
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

    def test_ports_getter(self):
        expected = [MagicMock(), MagicMock()]
        self.executor.ports = expected
        result = self.executor.ports

        self.assertCountEqual(result, expected)
        self.assertNotEqual(id(result), id(expected))

    @patch('scans.executor.NmapPortInfoTask')
    @patch('scans.executor.cfg', new_callable=Config)
    def test_scan_only(self, mock_cfg, mock_port_info):
        mock_cfg.get = MagicMock(return_value="0s")
        self.executor.scan_only = MagicMock()
        self.executor._get_ports_for_scanning = MagicMock(return_value=[MagicMock()])
        self.executor.run()

        result = mock_port_info.call_args[1].get('scan_only')
        expected = self.executor.scan_only

        self.assertEqual(result, expected)

    @patch('scans.executor.TaskMapper')
    def test_nodes(self, mock_task):
        self.executor._ports = []
        node_1 = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        node_2 = Node(ip=ipaddress.ip_address('127.0.0.2'), node_id=2)
        node_3 = Node(ip=ipaddress.ip_address('127.0.0.3'), node_id=3)
        self.executor.nodes = [node_1, node_2, node_3]
        self.executor.scan_only = False

        self.executor.run()
        mock_task.return_value.assign_tasks_for_node.assert_has_calls((call(node_1), call(node_2), call(node_3)))