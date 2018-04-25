"""
This module contains class for managing async tasks.

"""
from functools import partial
import logging as log
from threading import Thread

import time
from pycslib.utils import RabbitConsumer
from tornado import gen
from tornado.gen import sleep
from tornado.ioloop import IOLoop
from tornado.locks import Event
from tornado.queues import Queue, QueueEmpty

from aucote_cfg import cfg
from tools.common.command_task import CommandTask
from tools.common.port_scan_task import PortScanTask
from tools.nmap.tasks.port_info import NmapPortInfoTask
from utils.async_crontab_task import AsyncCrontabTask


class _Executor(Thread):
    """
    Tasks executor. Task is executed in ioloop for easier stopping it. Subprocess based tasks are killed external
    """
    def __init__(self, task, number, *args, **kwargs):
        super(_Executor, self).__init__(*args, **kwargs)
        self.ioloop = None
        self.task = task
        self.number = number

    def run(self):
        if self.task.cancelled:
            return

        self.task.executor = self

        self.ioloop = IOLoop()
        self.ioloop.make_current()
        self.ioloop.add_callback(self.execute)
        self.ioloop.start()
        self.task.clear()
        self.ioloop.clear_current()

    async def execute(self):
        """
        Update task and stop ioloop
        """
        try:
            await self.task()
        except:
            log.exception("Exception while executing task on worker %s", self.number)
        finally:
            self.ioloop.stop()
            self.task.finish_time = int(time.time())

    def stop(self):
        """
        Stop task. Important especially for Subprocess based tasks
        """
        self.task.kill()

        # As Subprocess based tasks generate traffic only using external tool, they should exit gracefully
        if not isinstance(self.task, (CommandTask, NmapPortInfoTask, PortScanTask)):
            self.ioloop.stop()

    def __str__(self):
        return str(self.task)


class AsyncTaskManager(object):
    """
    Aucote uses asynchronous task executed in ioloop. Some of them,
    especially scanners, should finish before ioloop will stop

    This class should be accessed by instance class method, which returns global instance of task manager

    """
    _instance = None

    TASKS_POLITIC_WAIT = 0
    TASKS_POLITIC_KILL_WORKING_FIRST = 1
    TASKS_POLITIC_KILL_PROPORTIONS = 2
    TASKS_POLITIC_KILL_WORKING = 3

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
        self._toucan_keys = {}

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
        Execute queue. Every task in executed in separated thread (_Executor)

        """
        log.info("Starting worker %s", number)
        while True:
            try:
                item = self._tasks.get_nowait()
                try:
                    log.debug("Worker %s: starting %s", number, item)
                    thread = _Executor(task=item, number=number)
                    self._task_workers[number] = thread
                    thread.start()

                    while thread.is_alive():
                        await sleep(0.5)
                except:
                    log.exception("Worker %s: exception occurred", number)
                finally:
                    log.debug("Worker %s: %s finished", number, item)
                    self._tasks.task_done()
                    log.debug("Tasks left in queue: %s", self.unfinished_tasks)
                    self._task_workers[number] = None
            except QueueEmpty:
                await gen.sleep(0.5)
                if self._stop_condition.is_set() and self._tasks.empty():
                    return
            finally:
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

    def cron_task(self, name):
        for task in self._cron_tasks:
            if task.NAME == name:
                return task

    def crontab_task(self, name):
        for task, crontab in self._cron_tasks.items():
            if task.NAME == name:
                return crontab

    def change_throttling_toucan(self, key, value):
        self.change_throttling(value)

    def change_throttling(self, new_value):
        """
        Change throttling value. Keeps throttling value between 0 and 1.

        Behaviour of algorithm is described in docs/throttling.md

        Only working tasks are closing here. Idle workers are stop by themselves

        """
        if new_value > 1:
            new_value = 1
        if new_value < 0:
            new_value = 0

        new_value = round(new_value * 100) / 100

        old_limit = self._limit
        self._limit = round(self._parallel_tasks * float(new_value))

        working_tasks = [number for number, task in self._task_workers.items() if task is not None]
        current_tasks = len(self._task_workers)

        task_politic = cfg['service.scans.task_politic']

        if task_politic == self.TASKS_POLITIC_KILL_WORKING_FIRST:
            tasks_to_kill = current_tasks - self._limit
        elif task_politic == self.TASKS_POLITIC_KILL_PROPORTIONS:
            tasks_to_kill = round((old_limit - self._limit) * len(working_tasks) / self._parallel_tasks)
        elif task_politic == self.TASKS_POLITIC_KILL_WORKING:
            tasks_to_kill = (old_limit - self._limit) - (len(self._task_workers) - len(working_tasks))
        else:
            tasks_to_kill = 0

        log.debug('%s tasks will be killed', tasks_to_kill)

        for number in working_tasks:
            if tasks_to_kill <= 0:
                break
            self._task_workers[number].stop()
            tasks_to_kill -= 1

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

        log.info("Changing throttling scan rate to %s", value)
        self._manager.change_throttling(value)
