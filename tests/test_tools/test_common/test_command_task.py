from subprocess import CalledProcessError
from unittest import TestCase
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import gen_test, AsyncTestCase

from structs import Port, Scan, ScanContext
from tools.common.command_task import CommandTask
from utils import Config
from utils.exceptions import StopCommandException


class CommandTaskTest(AsyncTestCase):
    def setUp(self):
        super(CommandTaskTest, self).setUp()
        self.aucote = MagicMock()
        self.port = Port(node=MagicMock(), transport_protocol=None, number=None)
        self.port.scan = Scan()
        self.command = MagicMock(NAME='test_name')
        future = Future()
        self.future_return = MagicMock()
        future.set_result(self.future_return)
        self.command.async_call = MagicMock(return_value=future)
        self.exploit = MagicMock()
        self.context = ScanContext(aucote=self.aucote, scanner=MagicMock(scan=Scan()))
        self.task = CommandTask(context=self.context, port=self.port, command=self.command, exploits=[self.exploit],
                                scan=self.context.scanner.scan)
        self.cfg = {
            'tools': {
                'test_name': {
                    'timeout': 0
                }
            }
        }

    def test_init(self):
        self.assertEqual(self.task._port, self.port)
        self.assertEqual(self.task.aucote, self.aucote)
        self.assertEqual(self.task.command, self.command)
        self.assertEqual(self.task.exploit, self.exploit)

    def test_prepare_args(self):
        self.assertRaises(NotImplementedError, self.task.prepare_args)

    @patch('time.time', MagicMock(return_value=5))
    @patch('tools.common.command_task.cfg', new_callable=Config)
    @patch('tools.common.command_task.Vulnerability')
    @gen_test
    async def test_call_ok(self, mock_vuln, cfg):
        cfg._cfg = self.cfg
        self.task.prepare_args = MagicMock()
        self.task.store_vulnerability = MagicMock()

        await self.task()

        self.command.async_call.assert_called_once_with(self.task.prepare_args(), timeout=0)
        mock_vuln.assert_called_once_with(exploit=self.exploit, port=self.port, output=self.future_return,
                                          context=self.context, scan=self.context.scanner.scan)
        self.task.store_vulnerability.assert_called_once_with(mock_vuln())

    @patch('tools.common.command_task.cfg', new_callable=Config)
    @patch('time.time', MagicMock(return_value=5))
    @gen_test
    async def test_call_without_results(self, cfg):
        cfg._cfg = self.cfg
        self.task.prepare_args = MagicMock()
        self.task.store_vulnerability = MagicMock()
        future = Future()
        future.set_result(None)
        self.command.async_call.return_value = future

        result = await self.task()
        self.assertEqual(result, None)

    @patch('tools.common.command_task.cfg', new_callable=Config)
    @patch('time.time', MagicMock(return_value=5))
    @gen_test
    async def test_call_with_exception(self, cfg):
        cfg._cfg = self.cfg
        self.task.prepare_args = MagicMock()
        self.task.store_vulnerability = MagicMock()
        self.command.async_call.side_effect = CalledProcessError(returncode=127, cmd='test')

        result = await self.task()
        args_storage = self.aucote.storage.save_security_scans.call_args[1]
        self.assertEqual(result, None)
        self.assertEqual(args_storage['port'].scan.end, 5)
        self.assertEqual(args_storage['port'].scan.start, 5)
        self.assertEqual(args_storage['exploits'], [self.exploit])

    @gen_test
    async def test_call_with_stop_task_exception(self):
        self.task.prepare_args = MagicMock()
        self.task.prepare_args.side_effect = StopCommandException

        result = await self.task()
        self.assertIsNone(result)
