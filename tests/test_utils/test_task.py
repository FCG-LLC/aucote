from unittest import TestCase
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from structs import Scan, TransportProtocol, Port
from utils.storage import Storage
from utils.task import Task


class TaskTest(TestCase):
    """
    Testing task behaviour
    """

    def setUp(self):
        """
        Set up init variables
        """
        self.executor = MagicMock()
        self.executor.kudu_queue = MagicMock()
        self.executor.exploits = MagicMock()

        self.task = Task(executor=self.executor)

    def test_init(self):
        """
        Test init and properties
        """
        self.assertEqual(self.task.executor, self.executor)
        self.assertEqual(self.task.kudu_queue, self.executor.kudu_queue)
        self.assertEqual(self.task.exploits, self.executor.exploits)

    def test_call(self):
        """
        Test call
        """
        self.assertRaises(NotImplementedError, self.task)

    def test_send_msg(self):
        """
        Task sending message
        """
        self.task.send_msg("TEST")
        self.executor.kudu_queue.send_msg.assert_called_once_with("TEST")

    @patch('utils.task.Storage')
    def test_store_scan(self, mock_storage):
        port = Port(node=None, number=80, transport_protocol=TransportProtocol.UDP)
        port.scan = Scan(end=25.0)
        exploit = Exploit(exploit_id=5)

        self.task.store_scan_end(exploits=[exploit], port=port)

        result = mock_storage.return_value.__enter__.return_value.save_scan.call_args[1]

        expected = {
            'exploit': exploit,
            'port': port
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(result['port'].scan.end, port.scan.end)