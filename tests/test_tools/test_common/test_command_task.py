from subprocess import CalledProcessError
from unittest import TestCase
from unittest.mock import MagicMock, patch

from structs import Port, Scan
from tools.common.command_task import CommandTask


class CommandTaskTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.port = Port(node=MagicMock(), transport_protocol=None, number=None)
        self.port.scan = Scan()
        self.command = MagicMock()
        self.exploit = MagicMock()
        self.task = CommandTask(aucote=self.aucote, port=self.port, command=self.command, exploits=[self.exploit])

    def test_init(self):
        self.assertEqual(self.task._port, self.port)
        self.assertEqual(self.task.aucote, self.aucote)
        self.assertEqual(self.task.command, self.command)
        self.assertEqual(self.task.exploit, self.exploit)

    def test_prepare_args(self):
        self.assertRaises(NotImplementedError, self.task.prepare_args)

    @patch('time.time', MagicMock(return_value=5))
    @patch('tools.common.command_task.Vulnerability')
    def test_call_ok(self, mock_vuln):
        self.task.prepare_args = MagicMock()
        self.task.store_vulnerability = MagicMock()

        self.task()

        self.command.call.assert_called_once_with(self.task.prepare_args.return_value)
        mock_vuln.assert_called_once_with(exploit=self.exploit, port=self.port,
                                                              output=self.command.call.return_value)
        self.task.store_vulnerability.assert_called_once_with(mock_vuln.return_value)

    @patch('time.time', MagicMock(return_value=5))
    def test_call_without_results(self):
        self.task.prepare_args = MagicMock()
        self.task.store_vulnerability = MagicMock()
        self.command.call.return_value = None

        result = self.task()
        self.assertEqual(result, None)

    @patch('time.time', MagicMock(return_value=5))
    def test_call_with_exception(self):
        self.task.prepare_args = MagicMock()
        self.task.store_vulnerability = MagicMock()
        self.command.call.side_effect = CalledProcessError(returncode=127, cmd='test')

        result = self.task()
        args_storage = self.aucote.storage.save_scans.call_args[1]
        self.assertEqual(result, None)
        self.assertEqual(args_storage['port'].scan.end, 0)
        self.assertEqual(args_storage['port'].scan.start, 0)
        self.assertEqual(args_storage['exploits'], [self.exploit])
