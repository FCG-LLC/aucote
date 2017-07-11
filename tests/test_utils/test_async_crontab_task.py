from functools import partial
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from utils.async_crontab_task import AsyncCrontabTask


class AsyncCrontabTaskTest(AsyncTestCase):
    @patch('utils.async_crontab_task.IOLoop')
    def setUp(self, mock_ioloop):
        super(AsyncCrontabTaskTest, self).setUp()
        self.func = MagicMock()
        self.func.__name__ = 'test_name'

        future = Future()
        future.set_result(MagicMock())
        self.func.return_value = future

        self.cron = '*/5 * * * *'
        self.task = AsyncCrontabTask(func=self.func, cron=self.cron)
        self.task._loop = MagicMock()
        self.mock_ioloop = mock_ioloop

    def test_init(self):
        self.assertEqual(self.task.func, self.func)
        self.assertEqual(self.task.cron, self.cron)
        self.assertFalse(self.task._is_running)
        self.assertFalse(self.task._stop)
        self.assertFalse(self.task._stop)

    def test_is_running(self):
        self.assertEqual(self.task.is_running(), self.task._is_running)

    def test_start(self):
        self.task._loop = MagicMock()
        self.task._started = False
        self.task.start()
        self.task._loop.call_later.assert_called_once_with(1, self.task)
        self.assertTrue(self.task._started)

    def test_start_if_started(self):
        self.task._loop = MagicMock()
        self.task._started = True
        self.task.start()
        self.assertFalse(self.task._loop.call_later.called)
        self.assertTrue(self.task._started)

    def test_stop(self):
        self.task._stop = False
        self.task.stop()
        self.assertTrue(self.task._stop)

    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=300))
    @gen_test
    def test_call(self):
        self.task._prepare_next_iteration = MagicMock()
        yield self.task()
        self.func.assert_called_once_with()
        self.task._prepare_next_iteration.assert_called_once_with()

    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=305))
    @gen_test
    def test_call_already_called(self):
        self.task._prepare_next_iteration = MagicMock()
        self.task._last_execute = 300
        yield self.task()
        self.assertFalse(self.func.called)
        self.task._prepare_next_iteration.assert_called_once_with()

    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=205))
    @gen_test
    def test_call_incorrect_time(self):
        self.task._prepare_next_iteration = MagicMock()
        yield self.task()
        self.assertFalse(self.func.called)
        self.task._prepare_next_iteration.assert_called_once_with()

    @patch('utils.async_crontab_task.log.exception')
    @patch('utils.async_crontab_task.time.time', MagicMock(return_value=300))
    @gen_test
    def test_call_with_exception(self, mock_exc):
        self.task._prepare_next_iteration = MagicMock()
        self.task.func.side_effect = (Exception(), )
        yield self.task()
        self.assertTrue(mock_exc.called)
        self.task._prepare_next_iteration.assert_called_once_with()

    @gen_test
    def test_stopping_cron_loop(self):
        self.task._prepare_next_iteration = MagicMock()
        self.task._stop = True

        yield self.task()
        self.assertFalse(self.task._prepare_next_iteration.called)

    def test_prepare_next_iteration(self):
        self.task._is_running = True
        self.task._prepare_next_iteration()

        self.assertFalse(self.task._is_running)
        self.task._loop.call_later.assert_called_once_with(1, self.task)

    def test_cron_callable(self):
        self.task._cron = MagicMock()
        self.assertEqual(self.task.cron, self.task._cron.return_value)

    @gen_test
    async def test_invalid_cron_value(self):
        self.task._cron = ''
        self.task._prepare_next_iteration = MagicMock()
        await self.task()
        self.assertFalse(self.func.called)
        self.task._prepare_next_iteration.assert_called_once_with()
