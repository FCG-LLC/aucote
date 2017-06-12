from functools import partial
from random import randint
from unittest.mock import MagicMock, patch, call

from tornado import gen
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test
from tornado_crontab import CronTabCallback

from utils.async_crontab_task import AsyncCrontabTask
from utils.async_task_manager import AsyncTaskManager


class TestAsyncTaskManager(AsyncTestCase):
    def setUp(self):
        super(TestAsyncTaskManager, self).setUp()

        self.task_1 = MagicMock()
        self.task_2 = MagicMock()
        AsyncTaskManager._instance = None
        self.task_manager = AsyncTaskManager.instance(parallel_tasks=1)
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

    def test_clear(self):
        self.task_manager._cron_tasks = MagicMock()
        self.task_manager.run_tasks = MagicMock()

        self.task_manager.clear()
        self.assertEqual(self.task_manager._cron_tasks, {})
        self.assertEqual(self.task_manager.run_tasks, {})

    @patch('utils.async_task_manager.IOLoop')
    @patch('utils.async_task_manager.partial')
    def test_start(self, mock_partial, mock_ioloop):
        self.task_manager._parallel_tasks = 2
        self.task_manager.start()
        self.task_1.start.assert_called_once_with()
        self.task_2.start.assert_called_once_with()
        mock_partial.has_calls((call(self.task_manager.process_tasks, 0), call(self.task_manager.process_tasks, 1)))
        mock_ioloop.current.return_value.add_callback.assert_has_calls((call(mock_partial.return_value),
                                                                        call(mock_partial.return_value)))

    @patch('utils.async_task_manager.IOLoop')
    @gen_test
    def test_stop(self, mock_ioloop):
        self.task_manager._tasks = MagicMock()
        future_tasks = Future()
        future_tasks.set_result(True)
        self.task_manager._tasks.join.return_value = future_tasks

        future_wait = Future()
        future_wait.set_result(True)
        self.task_manager._shutdown_condition.wait.return_value = future_wait

        self.task_manager.stop()
        self.task_1.stop.assert_called_once_with()
        self.task_2.stop.assert_called_once_with()
        mock_ioloop.current.return_value.add_callback.assert_called_once_with(self.task_manager.prepare_ioloop_shutdown)
        self.task_manager._shutdown_condition.wait.assert_called_once_with()
        self.task_manager._tasks.join.assert_called_once_with()

    def test_add_crontab_task(self):
        task = MagicMock()
        task.__name__ = 'test_name'
        self.task_manager.add_crontab_task(task, '* * * * *')

        self.assertIn('test_name', self.task_manager._cron_tasks.keys())
        self.assertIn('test_name', self.task_manager.run_tasks.keys())
        self.assertIsInstance(self.task_manager._cron_tasks.get('test_name'), AsyncCrontabTask)
        self.assertFalse(self.task_manager.run_tasks.get('test_name'))

    @gen_test
    def test_add_task(self):
        expected = MagicMock()
        self.task_manager.add_task(expected)
        result = yield self.task_manager._tasks.get()
        self.task_manager._tasks.task_done()
        self.assertEqual(result, expected)

    @gen_test
    def test_process_queue(self):
        task = MagicMock(return_value=Future())
        task.return_value.set_result(MagicMock())

        self.task_manager.add_task(task)

        self.io_loop.add_callback(partial(self.task_manager.process_tasks, 0))
        yield self.task_manager._tasks.join()
        task.assert_called_once_with()

    @patch('utils.async_task_manager.log.exception')
    @gen_test
    def test_process_queue_exception(self, mock_exception):
        task = MagicMock(side_effect=Exception())
        self.task_manager.add_task(task)

        self.io_loop.add_callback(partial(self.task_manager.process_tasks, 0))
        yield self.task_manager._tasks.join()
        self.assertTrue(mock_exception.called)

    def test_unfinished_tasks(self):
        tasks = randint(5, 10)
        for i in range(tasks):
            self.task_manager.add_task(i)

        self.assertEqual(self.task_manager.unfinished_tasks, tasks)
