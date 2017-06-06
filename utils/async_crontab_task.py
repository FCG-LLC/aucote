"""
Asynchronous Task controller. Executes task on given cron time

"""
import time
import logging as log
from croniter import croniter
from tornado.ioloop import PeriodicCallback, IOLoop


class AsyncCrontabTask(object):
    """
    Asynchronous Task controller. Executes task on given cron time. Maximum one this same time

    """
    def __init__(self, cron, func):
        self.cron = cron
        self._last_execute = None
        self._is_running = False
        self.func = func
        self._callback = PeriodicCallback(self, 1000, IOLoop.instance().current())

    async def __call__(self):
        """
        Execute function. Do it only if it is no currently executing

        Returns:
            None

        """
        if self._is_running:
            return

        self._is_running = True

        current_time = time.time()
        current_cron_time = int(current_time / 60) * 60
        current_cron = croniter(self.cron, current_time - 60).next()

        if current_cron != current_cron_time or current_cron_time == self._last_execute:
            self._is_running = False
            return

        self._last_execute = current_cron_time

        try:
            log.debug("AsyncCrontabTask[%s]: Executing", self.func.__name__)
            await self.func()
        except:
            log.exception("AsyncCrontabTask[%s]: Exception", self.func.__name__)
        finally:
            self._is_running = False
            log.debug("AsyncCrontabTask[%s]: Finished", self.func.__name__)

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
        self._callback.start()

    def stop(self):
        """
        Stop periodic function executing

        Returns:
            None

        """
        self._callback.stop()
