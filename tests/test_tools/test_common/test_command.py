import subprocess
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from tools.common import Command


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class CommandTest(AsyncTestCase):
    """
    Test system command with and without stderr.
    """

    SCRIPT_XML = b'''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    def setUp(self):
        super(CommandTest, self).setUp()
        self.command = Command()
        self.command.COMMON_ARGS = []

    @patch('tools.common.command.subprocess.run')
    def test_stderr(self, mock_run):
        mock_run.return_value = MagicMock(stdout=self.SCRIPT_XML, stderr=b'', returncode=1)
        self.assertRaises(subprocess.CalledProcessError, self.command.call)

    @patch('tools.common.command.process.Subprocess')
    @gen_test
    def test_async_call(self, mock_subprocess):
        future_1 = Future()
        future_1.set_result(0)
        mock_subprocess.return_value.wait_for_exit.return_value = future_1
        future_2 = Future()
        future_2.set_result(self.SCRIPT_XML)
        mock_subprocess.return_value.stdout.read_until_close.return_value = future_2
        future_3 = Future()
        future_3.set_result(b'')
        mock_subprocess.return_value.stderr.read_until_close.return_value = future_3

        result = yield self.command.async_call()
        self.assertEqual(result, self.SCRIPT_XML.decode("utf-8"))

    @patch('tools.common.command.process.Subprocess')
    @gen_test
    def test_async_call_with_exception(self, mock_subprocess):
        future_1 = Future()
        future_1.set_result(1)
        mock_subprocess.return_value.wait_for_exit.return_value = future_1
        future_2 = Future()
        future_2.set_result(self.SCRIPT_XML)
        mock_subprocess.return_value.stdout.read_until_close.return_value = future_2
        future_3 = Future()
        future_3.set_result("")
        mock_subprocess.return_value.stderr.read_until_close.return_value = future_3

        with self.assertRaises(subprocess.CalledProcessError):
            yield self.command.async_call()
