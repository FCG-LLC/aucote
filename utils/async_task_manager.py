"""
This module contains class for managing async tasks.

"""
from functools import partial
import logging as log

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.locks import Event
from tornado.queues import Queue

from utils.async_crontab_task import AsyncCrontabTask


class AsyncTaskManager(object):
    """
    Aucote uses asynchronous task executed in ioloop. Some of them,
    especially scanners, should finish before ioloop will stop

    This class should be accessed by instance class method, which returns global instance of task manager

    """
    _instance = None

    def __init__(self, parallel_tasks=10):
        self._shutdown_condition = Event()
        self._stop_condition = Event()
        self._cron_tasks = {}
        self.run_tasks = {}
        self._parallel_tasks = parallel_tasks
        self._tasks = Queue()
        self._task_workers = []

    @classmethod
    def instance(cls, *args, **kwargs):
        """
        Return instance of AsyncTaskManager

        Returns:
            AsyncTaskManager

        """
        if cls._instance is None:
            cls._instance = AsyncTaskManager(*args, **kwargs)
        return cls._instance

    @property
    def shutdown_condition(self):
        return self._shutdown_condition

    def start(self):
        """
        Start CronTabCallback tasks

        Returns:
            None

        """
        for task in self._cron_tasks.values():
            task.start()

        for number in range(self._parallel_tasks):
            self._task_workers.append(IOLoop.current().add_callback(partial(self.process_tasks, number)))

    def add_crontab_task(self, task, cron):
        """
        Add function to scheduler and execute at cron time

        Args:
            task (function):
            cron (str): crontab value

        Returns:
            None

        """

        self._cron_tasks[task.__name__] = AsyncCrontabTask(cron, task)
        self.run_tasks[task.__name__] = False

    @gen.coroutine
    def stop(self):
        """
        Stop CronTabCallback tasks and wait on them to finish

        Returns:
            None

        """
        for task in self._cron_tasks.values():
            task.stop()
        IOLoop.current().add_callback(self._prepare_shutdown)
        yield [self._stop_condition.wait(), self._tasks.join()]
        self._shutdown_condition.set()

    def _prepare_shutdown(self):
        """
        Check if ioloop can be stopped

        Returns:
            None

        """
        if any(task.is_running() for task in self._cron_tasks.values()) or any(self.run_tasks.values()):
            IOLoop.current().add_callback(self._prepare_shutdown)
            return

        self._stop_condition.set()

    def clear(self):
        """
        Clear list of tasks

        Returns:
            None

        """
        self._cron_tasks = {}
        self.run_tasks = {}
        self._shutdown_condition.clear()
        self._stop_condition.clear()

    async def process_tasks(self, number):
        """
        Execute queue

        Returns:
            None

        """
        log.info("Starting worker %s", number)
        async for item in self._tasks:
            try:
                log.debug("Worker %s: starting %s", number, item)
                await item()
            except:
                log.exception("Worker %s: exception occurred", number)
            finally:
                log.debug("Worker %s: %s finished", number, item)
                self._tasks.task_done()
                log.debug("Tasks left in queue: %s", self.unfinished_tasks)
        log.info("Closing worker %s", number)

    def add_task(self, task):
        """
        Add task to the queue

        Args:
            task:

        Returns:
            None

        """
        self._tasks.put(task)

    @property
    def unfinished_tasks(self):
        """
        Task which are still processed or in queue

        Returns:
            int

        """
        return self._tasks._unfinished_tasks
