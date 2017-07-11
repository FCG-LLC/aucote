"""
Asynchronous Task controller. Executes task on given cron time

"""
import time
import logging as log
from functools import partial

from croniter import croniter
from tornado.ioloop import IOLoop


class AsyncCrontabTask(object):
    """
    Asynchronous Task controller. Executes task on given cron time. No more than one at a time.

    If there is time to execute new task, but other task is already executing, the new task is ignored.
    If task is unfinishable, it would block executing new tasks.

    """
    def __init__(self, cron, func):
        self._cron = cron
        self._last_execute = None
        self._is_running = False
        self._started = False
        self._stop = False
        self.func = func
        self._loop = IOLoop.current().instance()

    @property
    def name(self):
        return str(self.func)

    @property
    def cron(self):
        """
        Cron value of current task

        Returns:
            str

        """
        if callable(self._cron):
            return self._cron()

        return self._cron

    async def __call__(self):
        """
        Execute function. Do it only if it is no currently executing

        Returns:
            None

        """
        if self._stop:
            self._started = False
            return

        self._is_running = True

        try:
            current_time = time.time()
            current_cron_time = int(current_time / 60) * 60
            current_cron = croniter(self.cron, current_time - 60).next()

            if current_cron != current_cron_time or current_cron_time == self._last_execute:
                return

            self._last_execute = current_cron_time

            log.debug("AsyncCrontabTask[%s]: Executing", self.name)
            await self.func()
            log.debug("AsyncCrontabTask[%s]: Finished", self.name)
        except Exception:
            log.exception("AsyncCrontabTask[%s]: Exception", self.name)
        finally:
            self._prepare_next_iteration()

    def is_running(self):
        """
        Check if function is currently executing

        Returns:
            None

        """
        return self._is_running

    def start(self):
        """
        Start periodic function executing

        Returns:
            None

        """
        if not self._started:
            self._started = True
            self._loop.call_later(1, self)

    def stop(self):
        """
        Stop periodic function executing

        Returns:
            None

        """
        self._stop = True

    def _prepare_next_iteration(self):
        self._is_running = False
        self._loop.call_later(1, self)
