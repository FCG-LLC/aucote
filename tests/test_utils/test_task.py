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

    @patch('utils.task.time.time', MagicMock(return_value=17))
    def setUp(self):
        """
        Set up init variables
        """
        self.executor = MagicMock()
        self.executor.kudu_queue = MagicMock()
        self.executor.exploits = MagicMock()
        self.scan = Scan()

        self.task = Task(aucote=self.executor, scan=self.scan)

    def test_init(self):
        """
        Test init and properties
        """
        self.assertEqual(self.task.aucote, self.executor)
        self.assertEqual(self.task.creation_time, 17)
        self.assertEqual(self.task.kudu_queue, self.executor.kudu_queue)

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

    def test_store_scan(self):
        port = Port(node=None, number=80, transport_protocol=TransportProtocol.UDP)
        port.scan = Scan(end=25.0)
        exploit = Exploit(exploit_id=5)

        self.task.store_scan_end(exploits=[exploit], port=port)

        self.task.aucote.storage.save_security_scans.assert_called_once_with(exploits=[exploit], port=port,
                                                                             scan=self.scan)
    def test_reload_config(self):
        result = self.task.reload_config()

        self.assertIsNone(result)

    def test_storage_property(self):
        self.assertEqual(self.executor.storage, self.task.storage)
