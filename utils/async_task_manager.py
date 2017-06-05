"""
This module contains class for managing async tasks.

"""
from functools import wraps
import logging as log

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.locks import Event
from tornado.queues import Queue
from tornado_crontab import CronTabCallback


class AsyncTaskManager(object):
    """
    Aucote uses asynchronous task executed in ioloop. Some of them,
    especially scanners, should finish before ioloop will stop

    This class should be accessed by instance class method, which returns global instance of task manager

    """
    _instance = None

    def __init__(self, parallel_tasks=10):
        self._shutdown_condition = Event()
        self._cron_tasks = {}
        self.run_tasks = {}
        self._tasks = Queue(maxsize=parallel_tasks)

    @classmethod
    def instance(cls):
        """
        Return instance of AsyncTaskManager

        Returns:
            AsyncTaskManager

        """
        if cls._instance is None:
            cls._instance = AsyncTaskManager()
        return cls._instance

    def start(self):
        """
        Start CronTabCallback tasks

        Returns:
            None

        """
        for task in self._cron_tasks.values():
            task.start()
        IOLoop.current().add_callback(self.process_tasks)

    def add_crontab_task(self, task, cron):
        """
        Add function to scheduler and execute at cron time

        Args:
            task (function):
            cron (str): crontab value

        Returns:
            None

        """

        self._cron_tasks[task.__name__] = CronTabCallback(task, cron, io_loop=IOLoop.current())
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
        IOLoop.current().add_callback(self.prepare_ioloop_shutdown)
        yield [self._shutdown_condition.wait(), self._tasks.join()]

    @classmethod
    def unique_task(cls, function):
        """
        Decorator which allow execution only one instance of function this same time

        Args:
            function:

        Returns:
            function

        """
        @gen.coroutine
        @wraps(function)
        def return_function(*args, **kwargs):
            """
            Wrapper on original function

            Args:
                *args:
                **kwargs:

            Returns:
                None

            """
            log.debug("UniqueTask: %s attempts to start")
            if cls._instance.run_tasks[function.__name__]:
                log.debug("UniqueTask: %s didn't started")
                return
            log.debug("UniqueTask: %s started")

            cls._instance.run_tasks[function.__name__] = True
            try:
                yield function(*args, **kwargs)
            except Exception:
                log.exception("Exception while running %s", function.__name__)
            finally:
                log.debug("UniqueTask: %s finished")
                cls._instance.run_tasks[function.__name__] = False

        return return_function

    def prepare_ioloop_shutdown(self):
        """
        Check if ioloop can be stopped

        Returns:
            None

        """
        if any(task.is_running() for task in self._cron_tasks.values()) or any(self.run_tasks.values()):
            IOLoop.current().add_callback(self.prepare_ioloop_shutdown)
            return

        self._shutdown_condition.set()

    def clear(self):
        """
        Clear list of tasks

        Returns:
            None

        """
        self._cron_tasks = {}
        self.run_tasks = {}

    async def process_tasks(self):
        """
        Execute queue

        Returns:
            None

        """
        async for item in self._tasks:
            try:
                log.debug("Executing %s", item)
                await item()
            finally:
                self._tasks.task_done()

    def add_task(self, task):
        """
        Add task to the queue

        Args:
            task:

        Returns:
            None

        """
        self._tasks.put(task)
