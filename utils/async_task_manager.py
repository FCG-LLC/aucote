"""
This module contains class for managing async tasks.

"""
from functools import partial
import logging as log

from pycslib.utils import RabbitConsumer
from tornado import gen
from tornado.gen import sleep
from tornado.ioloop import IOLoop
from tornado.locks import Event
from tornado.queues import Queue

from aucote_cfg import cfg
from utils.async_crontab_task import AsyncCrontabTask


class AsyncTaskManager(object):
    """
    Aucote uses asynchronous task executed in ioloop. Some of them,
    especially scanners, should finish before ioloop will stop

    This class should be accessed by instance class method, which returns global instance of task manager

    """
    _instance = None
    THROTTLE_POLL_TIME = 60

    def __init__(self, parallel_tasks=10):
        self._shutdown_condition = Event()
        self._stop_condition = Event()
        self._cron_tasks = {}
        self._parallel_tasks = parallel_tasks
        self._tasks = Queue()
        self._task_workers = {}
        self._events = {}
        self._limit = self._parallel_tasks
        self._next_task_number = 0

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
        """
        Event which is resolved if every job is done and AsyncTaskManager is ready to shutdown

        Returns:
            Event
        """
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
            self._task_workers[number] = IOLoop.current().add_callback(partial(self.process_tasks, number))

        self._next_task_number = self._parallel_tasks
        IOLoop.current().add_callback(self.monitor_limit)

    def add_crontab_task(self, task, cron, event=None):
        """
        Add function to scheduler and execute at cron time

        Args:
            task (function):
            cron (str): crontab value
            event (Event): event which prevent from running task with similar aim, eg. security scans

        Returns:
            None

        """
        if event is not None:
            event = self._events.setdefault(event, Event())
        self._cron_tasks[task] = AsyncCrontabTask(cron, task, event)

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
        if any(task.is_running() for task in self._cron_tasks.values()):
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
                self._task_workers[number] = item
                await item()
            except:
                log.exception("Worker %s: exception occurred", number)
            finally:
                log.debug("Worker %s: %s finished", number, item)
                self._tasks.task_done()
                log.debug("Tasks left in queue: %s", self.unfinished_tasks)
                self._task_workers[number] = None

                if self._limit < len(self._task_workers):
                    break

        del self._task_workers[number]

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

    @property
    def cron_tasks(self):
        """
        List of cron tasks

        Returns:
            list

        """
        return self._cron_tasks.keys()

    async def monitor_limit(self):
        """
        Poll configuration for throttling value
        """
        throttling = await cfg.toucan.get('throttling.rate', add_prefix=False) if cfg.toucan is not None else 1

        self.change_throttling(throttling)

        await sleep(self.THROTTLE_POLL_TIME)
        IOLoop.current().add_callback(self.monitor_limit)

    def change_throttling(self, new_value):
        """
        Change throttling value
        """
        self._limit = round(self._parallel_tasks * float(new_value))

        current_tasks = len(self._task_workers)

        for number in range(self._limit - current_tasks):
            self._task_workers[self._next_task_number] = None
            IOLoop.current().add_callback(partial(self.process_tasks, self._next_task_number))
            self._next_task_number += 1


class ThrottlingConsumer(RabbitConsumer):
    """
    Throttling consumer for rabbit queue
    """
    def __init__(self, manager):
        self._manager = manager
        super(ThrottlingConsumer, self).__init__('toucan', 'topic', 'toucan.config.throttling.rate')

    async def process_message(self, msg):
        """
        Process message and set new throttling value
        """
        if msg.routing_key != 'toucan.config.throttling.rate':
            return
        value = float(msg.json()['value'])
        log.info("Changing scan throttling to %s", value)
        self._manager.change_throttling(value)
