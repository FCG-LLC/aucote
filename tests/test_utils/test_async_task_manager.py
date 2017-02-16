from unittest.mock import MagicMock, patch

from tornado import gen
from tornado.testing import AsyncTestCase, gen_test

from utils.async_task_manager import AsyncTaskManager


class TestAsyncTaskManager(AsyncTestCase):
    def setUp(self):
        super(TestAsyncTaskManager, self).setUp()
        self.task_1 = MagicMock()
        self.task_2 = MagicMock()
        AsyncTaskManager.add_task('task_1', self.task_1)
        AsyncTaskManager.add_task('task_2', self.task_2)
        AsyncTaskManager._SHUTDOWN_CONDITION = MagicMock()

        AsyncTaskManager._SHUTDOWN_CONDITION = MagicMock()

    def tearDown(self):
        AsyncTaskManager.clear()

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown(self, mock_ioloop):
        AsyncTaskManager._CRON_TASKS['task_1'].is_running.return_value = False
        AsyncTaskManager._CRON_TASKS['task_2'].is_running.return_value = False

        AsyncTaskManager._RUN_TASKS = {'task_1': False, 'task_2': False}

        AsyncTaskManager.monitor_ioloop_shutdown()

        AsyncTaskManager._SHUTDOWN_CONDITION.set.assert_called_once_with()

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown_failed_because_of_task(self, mock_ioloop):
        AsyncTaskManager._CRON_TASKS['task_1'].is_running.return_value = False
        AsyncTaskManager._CRON_TASKS['task_2'].is_running.return_value = False

        AsyncTaskManager._RUN_TASKS = {'task_1': False, 'task_2': True}

        AsyncTaskManager.monitor_ioloop_shutdown()

        self.assertFalse(AsyncTaskManager._SHUTDOWN_CONDITION.set.called)

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown_failed_because_of_cron_task(self, mock_ioloop):
        AsyncTaskManager._CRON_TASKS['task_1'].is_running.return_value = True
        AsyncTaskManager._CRON_TASKS['task_2'].is_running.return_value = False

        AsyncTaskManager._RUN_TASKS = {'task_1': False, 'task_2': False}

        AsyncTaskManager.monitor_ioloop_shutdown()

        self.assertFalse(AsyncTaskManager._SHUTDOWN_CONDITION.set.called)

    @gen_test
    def test_decorator(self):
        @AsyncTaskManager.lock_task
        @gen.coroutine
        def task_1():
            self.task_1()

        yield task_1()
        self.task_1.assert_called_once_with()

    @gen_test
    def test_decorator_second_run(self):
        AsyncTaskManager._RUN_TASKS = {'task_1': True, 'task_2': False}

        @AsyncTaskManager.lock_task
        @gen.coroutine
        def task_1():
            self.task_1()

        yield task_1()
        self.assertFalse(self.task_1.called)

    def test_clear(self):
        AsyncTaskManager._CRON_TASKS = MagicMock()
        AsyncTaskManager._RUN_TASKS = MagicMock()

        AsyncTaskManager.clear()
        self.assertEqual(AsyncTaskManager._CRON_TASKS, {})
        self.assertEqual(AsyncTaskManager._RUN_TASKS, {})

    def test_start(self):
        AsyncTaskManager.start()
        self.task_1.start.assert_called_once_with()
        self.task_2.start.assert_called_once_with()

    @patch('utils.async_task_manager.IOLoop')
    def test_stop(self, mock_ioloop):
        AsyncTaskManager.stop()
        self.task_1.stop.assert_called_once_with()
        self.task_2.stop.assert_called_once_with()
        mock_ioloop.current.return_value.add_callback.assert_called_once_with(AsyncTaskManager.monitor_ioloop_shutdown)
        AsyncTaskManager._SHUTDOWN_CONDITION.wait.assert_called_once_with()
