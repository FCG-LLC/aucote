from unittest import TestCase
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from utils.async_crontab_task import AsyncCrontabTask


class AsyncCrontabTaskTest(AsyncTestCase):
    @patch('utils.async_crontab_task.IOLoop')
    @patch('utils.async_crontab_task.PeriodicCallback')
    def setUp(self, mock_callback, mock_ioloop):
        super(AsyncCrontabTaskTest, self).setUp()
        self.func = MagicMock()
        self.func.__name__ = 'test_name'

        future = Future()
        future.set_result(MagicMock())
        self.func.return_value = future

        self.cron = '*/5 * * * *'
        self.task = AsyncCrontabTask(func=self.func, cron=self.cron)
        self.callback = mock_callback
        self.mock_ioloop = mock_ioloop

    def test_init(self):
        self.assertEqual(self.task.func, self.func)
        self.assertEqual(self.task.cron, self.cron)
        self.assertFalse(self.task._is_running)
        self.assertEqual(self.task._callback, self.callback.return_value)
        self.callback.assert_called_once_with(self.task, 1000, self.mock_ioloop.instance().current())

    def test_is_running(self):
        self.assertEqual(self.task.is_running(), self.task._is_running)

    def test_start(self):
        self.task.start()
        self.task._callback.start.assert_called_once_with()

    def test_stop(self):
        self.task.stop()
        self.task._callback.stop.assert_called_once_with()

    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=300))
    @gen_test
    def test_call(self):
        yield self.task()
        self.func.assert_called_once_with()

    @gen_test
    def test_call_already_calling(self):
        self.task._is_running = True
        yield self.task()
        self.assertFalse(self.func.called)

    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=305))
    @gen_test
    def test_call_already_called(self):
        self.task._last_execute = 300
        yield self.task()
        self.assertFalse(self.func.called)

    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=205))
    @gen_test
    def test_call_incorrect_time(self):
        yield self.task()
        self.assertFalse(self.func.called)

    @patch('utils.async_crontab_task.log.exception')
    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=300))
    @gen_test
    def test_call_with_exception(self, mock_exc):
        self.task.func.side_effect = (Exception(), )
        yield self.task()
        self.assertTrue(mock_exc.called)
