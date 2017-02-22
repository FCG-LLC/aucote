from unittest.mock import MagicMock, patch

from tornado import gen
from tornado.testing import AsyncTestCase, gen_test
from tornado_crontab import CronTabCallback

from utils.async_task_manager import AsyncTaskManager


class TestAsyncTaskManager(AsyncTestCase):
    def setUp(self):
        super(TestAsyncTaskManager, self).setUp()
        self.task_1 = MagicMock()
        self.task_2 = MagicMock()
        self.task_manager = AsyncTaskManager.instance()
        self.task_manager._shutdown_condition = MagicMock()
        self.task_manager._cron_tasks['task_1'] = self.task_1
        self.task_manager._cron_tasks['task_2'] = self.task_2
        self.task_manager.run_tasks['task_1'] = False
        self.task_manager.run_tasks['task_2'] = False

    def tearDown(self):
        self.task_manager.clear()

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown(self, mock_ioloop):
        self.task_manager._cron_tasks['task_1'].is_running.return_value = False
        self.task_manager._cron_tasks['task_2'].is_running.return_value = False

        self.task_manager.run_tasks = {'task_1': False, 'task_2': False}

        self.task_manager.prepare_ioloop_shutdown()

        self.task_manager._shutdown_condition.set.assert_called_once_with()

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown_failed_because_of_task(self, mock_ioloop):
        self.task_manager._cron_tasks['task_1'].is_running.return_value = False
        self.task_manager._cron_tasks['task_2'].is_running.return_value = False

        self.task_manager.run_tasks = {'task_1': False, 'task_2': True}

        self.task_manager.prepare_ioloop_shutdown()

        self.assertFalse(self.task_manager._shutdown_condition.set.called)

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown_failed_because_of_cron_task(self, mock_ioloop):
        self.task_manager._cron_tasks['task_1'].is_running.return_value = True
        self.task_manager._cron_tasks['task_2'].is_running.return_value = False

        self.task_manager.run_tasks = {'task_1': False, 'task_2': False}

        self.task_manager.prepare_ioloop_shutdown()

        self.assertFalse(self.task_manager._shutdown_condition.set.called)

    @gen_test
    def test_decorator(self):
        @AsyncTaskManager.unique_task
        @gen.coroutine
        def task_1():
            self.task_1()

        yield task_1()
        self.task_1.assert_called_once_with()

    @gen_test
    def test_decorator_second_run(self):
        self.task_manager.run_tasks = {'task_1': True, 'task_2': False}

        @AsyncTaskManager.unique_task
        @gen.coroutine
        def task_1():
            self.task_1()

        yield task_1()
        self.assertFalse(self.task_1.called)

    def test_clear(self):
        self.task_manager._cron_tasks = MagicMock()
        self.task_manager.run_tasks = MagicMock()

        self.task_manager.clear()
        self.assertEqual(self.task_manager._cron_tasks, {})
        self.assertEqual(self.task_manager.run_tasks, {})

    def test_start(self):
        self.task_manager.start()
        self.task_1.start.assert_called_once_with()
        self.task_2.start.assert_called_once_with()

    @patch('utils.async_task_manager.IOLoop')
    def test_stop(self, mock_ioloop):
        self.task_manager.stop()
        self.task_1.stop.assert_called_once_with()
        self.task_2.stop.assert_called_once_with()
        mock_ioloop.current.return_value.add_callback.assert_called_once_with(self.task_manager.prepare_ioloop_shutdown)
        self.task_manager._shutdown_condition.wait.assert_called_once_with()

    def test_add_crontab_task(self):
        task = MagicMock()
        task.__name__ = 'test_name'
        self.task_manager.add_crontab_task(task, '* * * * *')

        self.assertIn('test_name', self.task_manager._cron_tasks.keys())
        self.assertIn('test_name', self.task_manager.run_tasks.keys())
        self.assertIsInstance(self.task_manager._cron_tasks.get('test_name'), CronTabCallback)
        self.assertFalse(self.task_manager.run_tasks.get('test_name'))
