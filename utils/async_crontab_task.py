"""
Asynchronous Task controller. Executes task on given cron time

"""
import time
import logging as log
from croniter import croniter, CroniterBadCronError
from tornado.ioloop import IOLoop


class AsyncCrontabTask(object):
    """
    Asynchronous Task controller. Executes task on given cron time. No more than one at a time.

    If there is time to execute new task, but other task is already executing, the new task is ignored.
    If task is unfinishable, it would block executing new tasks.

    """
    def __init__(self, cron, func, event=None):
        self._cron = cron
        self._last_execute = None
        self._is_running = False
        self._started = False
        self._stop = False
        self.func = func
        self._event = event
        self._loop = IOLoop.current().instance()

    @property
    def name(self):
        """
        Name of cron job

        Returns:
            str

        """
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
            try:
                current_cron = croniter(self.cron, current_time - 60).next()
            except CroniterBadCronError:
                log.error("AsyncCrontabTask[%s]: %s is invalid cron value. Skipping scan", self.name, self.cron)
                return

            if not self.func.run_now:
                # Check if time meet the cron time
                if current_cron != current_cron_time:
                    await self.func.update_scan_status()
                    return

                # Check if task was already executed in this cron minute
                if current_cron_time == self._last_execute:
                    return

            self._last_execute = current_cron_time

            log.debug("AsyncCrontabTask[%s]: Executing", self.name)
            if self._event is not None and self._event.is_set():
                await self._event.wait()
                if time.time() - current_cron_time > 60:
                    log.warning("Cannot run scan because similar scan is already scanning")
                    return

            # Do not autostart scan next time
            self.func.run_now = False

            if self._event is not None:
                self._event.set()
            try:
                await self.func()
            finally:
                if self._event is not None:
                    self._event.clear()

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
        self._loop.call_later(60 - int(time.time()) % 60, self)
