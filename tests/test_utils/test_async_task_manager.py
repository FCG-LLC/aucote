from functools import partial
from random import randint
from unittest.mock import MagicMock, patch, call

from tornado.concurrent import Future
from tornado.queues import QueueEmpty
from tornado.testing import AsyncTestCase, gen_test

from utils.async_crontab_task import AsyncCrontabTask
from utils.async_task_manager import AsyncTaskManager, _Executor


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

    @gen_test
    def test_process_queue(self):
        future = Future()
        future.set_result(MagicMock())
        task = MagicMock(return_value=future)

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
        task.assert_called_once_with()

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


class _ExecutorTest(AsyncTestCase):
    def setUp(self):
        super(_ExecutorTest, self).setUp()
        self.task = MagicMock()
        self.executor = _Executor(task=self.task, number=13)

    @gen_test()
    async def test_execute(self):
        self.task.return_value = Future()
        self.task.return_value.set_exception(Exception())

        self.executor.ioloop = MagicMock()
        await self.executor.execute()

        self.executor.ioloop.stop.assert_called_once()
