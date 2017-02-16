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

    @patch('subprocess.check_output', MagicMock(return_value=SCRIPT_XML))
    def test_stdout(self):
        result = self.command.call()
        self.assertEqual(result, self.SCRIPT_XML.decode("utf-8"))

    @patch('subprocess.check_output', MagicMock(side_effect=subprocess.CalledProcessError(returncode=1, cmd='masscan')))
    def test_stderr(self):
        self.assertRaises(subprocess.CalledProcessError, self.command.call)

    @patch('tools.common.command.process.Subprocess')
    @gen_test
    def test_async_call(self, mock_subprocess):
        future_1 = Future()
        future_1.set_result(1)
        mock_subprocess.return_value.wait_for_exit.return_value = future_1
        future_2 = Future()
        future_2.set_result(self.SCRIPT_XML)
        mock_subprocess.return_value.stdout.read_until_close.return_value = future_2
        result = yield self.command.async_call()
        self.assertEqual(result, self.SCRIPT_XML.decode("utf-8"))

    @patch('tools.common.command.process.Subprocess')
    @gen_test
    def test_async_call_with_exception(self, mock_subprocess):
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'test')
        try:
            yield self.command.async_call()
            self.fail()
        except subprocess.CalledProcessError:
            pass
