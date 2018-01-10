from functools import partial
from random import randint
from unittest.mock import MagicMock, patch, call

from tornado.concurrent import Future
from tornado.queues import QueueEmpty
from tornado.testing import AsyncTestCase, gen_test

from utils import Config
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
        self.task_manager._stop_condition = MagicMock()
        self.task_manager._cron_tasks['task_1'] = self.task_1
        self.task_manager._cron_tasks['task_2'] = self.task_2
        self.task_manager._task_workers = {0: None}
        self.tasks = {
            0: MagicMock(),
            1: MagicMock(),
            2: MagicMock(),
            3: MagicMock(),
            4: MagicMock(),
            5: None,
            6: None,
            7: None,
            8: None,
            9: None
        }

    def tearDown(self):
        self.task_manager.clear()

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown(self, mock_ioloop):
        self.task_manager._cron_tasks['task_1'].is_running.return_value = False
        self.task_manager._cron_tasks['task_2'].is_running.return_value = False

        self.task_manager.run_tasks = {'task_1': False, 'task_2': False}

        self.task_manager._prepare_shutdown()

        self.task_manager._stop_condition.set.assert_called_once_with()

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown_failed_because_of_task(self, mock_ioloop):
        self.task_manager._cron_tasks['task_1'].is_running.return_value = False
        self.task_manager._cron_tasks['task_2'].is_running.return_value = False

        self.task_manager.run_tasks = {'task_1': False, 'task_2': True}

        self.task_manager._prepare_shutdown()

        self.assertFalse(self.task_manager._shutdown_condition.set.called)

    @patch('utils.async_task_manager.IOLoop')
    def test_monitor_ioloop_shutdown_failed_because_of_cron_task(self, mock_ioloop):
        self.task_manager._cron_tasks['task_1'].is_running.return_value = True
        self.task_manager._cron_tasks['task_2'].is_running.return_value = False

        self.task_manager.run_tasks = {'task_1': False, 'task_2': False}

        self.task_manager._prepare_shutdown()

        self.assertFalse(self.task_manager._shutdown_condition.set.called)

    def test_clear(self):
        self.task_manager._cron_tasks = MagicMock()
        self.task_manager.run_tasks = MagicMock()

        self.task_manager.clear()
        self.assertEqual(self.task_manager._cron_tasks, {})

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
        self.task_manager._stop_condition.wait.return_value = future_wait

        self.task_manager.stop()
        self.task_1.stop.assert_called_once_with()
        self.task_2.stop.assert_called_once_with()
        mock_ioloop.current.return_value.add_callback.assert_called_once_with(self.task_manager._prepare_shutdown)
        self.task_manager._stop_condition.wait.assert_called_once_with()
        self.task_manager._tasks.join.assert_called_once_with()
        self.task_manager._shutdown_condition.set.assert_called_once_with()

    def test_add_crontab_task(self):
        task = MagicMock()
        task.__name__ = 'test_name'
        self.task_manager.add_crontab_task(task, '* * * * *')

        self.assertIn(task, self.task_manager._cron_tasks.keys())
        self.assertIsInstance(self.task_manager._cron_tasks.get(task), AsyncCrontabTask)

    @patch('utils.async_task_manager.Event')
    def test_add_crontab_task_with_new_event(self, Event):
        task = MagicMock()
        task.__name__ = 'test_name'
        self.task_manager.add_crontab_task(task, '* * * * *', event='test')

        Event.assert_called_once_with()
        self.assertIn(task, self.task_manager._cron_tasks.keys())
        self.assertIsInstance(self.task_manager._cron_tasks.get(task), AsyncCrontabTask)
        self.assertEqual(self.task_manager._cron_tasks.get(task)._event, Event.return_value)

    def test_add_crontab_task_with_exists_event(self):
        task = MagicMock()
        task.__name__ = 'test_name'
        event = MagicMock()
        self.task_manager._events['test'] = event

        self.task_manager.add_crontab_task(task, '* * * * *', event='test')

        self.assertIn(task, self.task_manager._cron_tasks.keys())
        self.assertIsInstance(self.task_manager._cron_tasks.get(task), AsyncCrontabTask)
        self.assertEqual(self.task_manager._cron_tasks.get(task)._event, event)

    @gen_test
    def test_add_task(self):
        expected = MagicMock()
        self.task_manager.add_task(expected)
        result = yield self.task_manager._tasks.get()
        self.task_manager._tasks.task_done()
        self.assertEqual(result, expected)

    @patch('utils.async_task_manager.Task')
    @gen_test
    def test_process_queue(self, mock_task):
        self.task_manager.cancellable_executor = MagicMock()

        future = Future()
        future.set_result(MagicMock())
        task = MagicMock(return_value=future)

        mock_task.return_value = Future()
        mock_task.return_value.set_result(MagicMock())

        class queue(MagicMock):
            def __init__(self, task):
                super(queue, self).__init__()
                self._end = False
                self._task = task

            def get_nowait(self):
                if not self._end:
                    return self._task
                raise QueueEmpty

            def empty(self):
                return True

            async def __aiter__(self):
                return self

            async def __anext__(self):
                if not self._end:
                    return self._task
                raise StopAsyncIteration

            def task_done(self):
                self._end = True

            @property
            def _unfinished_tasks(self):
                return 0

        self.task_manager._tasks = queue(task)

        yield self.task_manager.process_tasks(0)
        mock_task.assert_called_once_with(self.task_manager.cancellable_executor.return_value)
        self.task_manager.cancellable_executor.assert_called_once_with(task)

    @patch('utils.async_task_manager.log.exception')
    @patch('utils.async_task_manager.Task')
    @gen_test
    async def test_process_queue_exception(self, mock_task, mock_exception):
        task = MagicMock(side_effect=Exception())
        self.task_manager.add_task(task)

        self.io_loop.add_callback(partial(self.task_manager.process_tasks, 0))
        await self.task_manager._tasks.join()
        self.assertTrue(mock_exception.called)

    def test_unfinished_tasks(self):
        tasks = randint(5, 10)
        for i in range(tasks):
            self.task_manager.add_task(i)

        self.assertEqual(self.task_manager.unfinished_tasks, tasks)

    def test_shutdown_condition(self):
        self.assertEqual(self.task_manager.shutdown_condition, self.task_manager._shutdown_condition)

    def test_cron_tasks(self):
        self.task_manager._cron_tasks = {
            MagicMock(): 'a',
            MagicMock(): 'b',
            MagicMock(): 'c',
            MagicMock(): 'd',
        }

        expected = self.task_manager._cron_tasks.keys()
        result = self.task_manager.cron_tasks

        self.assertEqual(result, expected)

    @patch('utils.async_task_manager.cfg', new_callable=Config)
    def test_change_throttling(self, cfg):
        cfg['service.scans.task_politic'] = 1

        self.task_manager._task_workers = self.tasks
        self.task_manager._cancellable_tasks = self.tasks
        self.task_manager._parallel_tasks = 10
        self.task_manager._limit = 10
        self.task_manager.change_throttling(0.6)

        self.assertTrue(all([
            self.tasks[0].cancel.called,
            self.tasks[1].cancel.called,
            self.tasks[2].cancel.called,
            self.tasks[3].cancel.called,
        ]))

        self.assertFalse(any([self.tasks[4].cancel.called]))

    @patch('utils.async_task_manager.cfg', new_callable=Config)
    def test_change_throttling_kill_idle_first(self, cfg):
        cfg['service.scans.task_politic'] = 3

        self.task_manager._task_workers = self.tasks
        self.task_manager._cancellable_tasks = self.tasks
        self.task_manager._parallel_tasks = 10
        self.task_manager._limit = 10
        self.task_manager.change_throttling(0.4)

        self.assertTrue(all([
            self.tasks[0].cancel.called
        ]))

        self.assertFalse(any([
            self.tasks[1].cancel.called,
            self.tasks[2].cancel.called,
            self.tasks[3].cancel.called,
            self.tasks[4].cancel.called
        ]))

    @patch('utils.async_task_manager.cfg', new_callable=Config)
    def test_change_throttling_scaled(self, cfg):
        cfg['service.scans.task_politic'] = 2

        self.task_manager._task_workers = self.tasks
        self.task_manager._cancellable_tasks = self.tasks
        self.task_manager._parallel_tasks = 10
        self.task_manager._limit = 10
        self.task_manager.change_throttling(0.6)

        self.assertTrue(all([
            self.tasks[0].cancel.called,
            self.tasks[1].cancel.called,
        ]))

        self.assertFalse(any([
            self.tasks[2].cancel.called,
            self.tasks[3].cancel.called,
            self.tasks[4].cancel.called
        ]))

    @patch('utils.async_task_manager.cfg', new_callable=Config)
    def test_change_throttling_scaled_non_1(self, cfg):
        cfg['service.scans.task_politic'] = 2

        self.task_manager._task_workers = self.tasks
        self.task_manager._cancellable_tasks = self.tasks
        self.task_manager._parallel_tasks = 10
        self.task_manager._limit = 10
        self.task_manager.change_throttling(0.6)

        self.assertTrue(all([
            self.tasks[0].cancel.called,
            self.tasks[1].cancel.called,
        ]))

        self.assertFalse(any([
            self.tasks[2].cancel.called,
            self.tasks[3].cancel.called,
            self.tasks[4].cancel.called
        ]))
