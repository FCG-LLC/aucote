"""
Abstract class for tasks. Provides interface compatible with task manager.
All Task based class should override __call__ function

"""
import logging as log
import time

from database.serializer import Serializer


class Task(object):
    """
    Base class for tasks, e.g. scan, nmap, hydra

    """
    def __init__(self, context):
        """
        Assign executor

        """
        self.context = context
        self.creation_time = time.time()
        self.start_time = None
        self.finish_time = None
        self._name = None
        self._cancelled = False
        self.executor = None

    @property
    def cancelled(self):
        return self._cancelled

    @property
    def aucote(self):
        return self.context.aucote

    @property
    def kudu_queue(self):
        """
        Return executors kudu_queue

        """
        return self.aucote.kudu_queue

    async def __call__(self, *args, **kwargs):
        try:
            self._prepare()
            return await self.execute(*args, **kwargs)
        finally:
            self._clean()

    async def execute(self, *args, **kwargs):
        raise NotImplementedError

    def send_msg(self, msg):
        """
        Send msg to kudu_queue

        """
        return self.kudu_queue.send_msg(msg)

    def _prepare(self):
        pass

    def _clean(self):
        pass

    def store_scan_end(self, exploits, port):
        """
        Stores scan end in local storage

        Args:
            exploits (Exploits):
            port (Port):

        Returns:
            None

        """
        self.aucote.storage.save_security_scans(exploits=exploits, port=port, scan=self.scan)

    def store_vulnerability(self, vuln):
        """
        Saves vulnerability into database (kudu)
        """
        if self.filter_out_vulnerability(vuln):
            self.context.scanner.store_vulnerability(vuln)

    def store_vulnerabilities(self, vulnerabilities):
        """
        Saves vulnerabilities into storage

        Args:
            vulnerabilities (list):

        Returns:
            None

        """
        log.info("Saving %i vulnerabilities", len(vulnerabilities))

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                self.store_vulnerability(vulnerability)

    def reload_config(self):
        """
        Should be executed by executor when, configuration is reloaded

        Returns:
            None

        """
        pass

    @property
    def storage(self):
        """
        Storage for aucote application

        Returns:
            Storage

        """
        return self.aucote.storage

    def additional_info(self):
        """
        Additional info which should be used in task name
        """
        return ''

    def __str__(self):
        return '[{status}] [{scan}] {task_name} [{info}]'.format(
            scan=self.scan_name,
            status='-' if self._cancelled is True else '+', task_name=self.__class__.__name__,
            info=self.additional_info()
        )

    @property
    def scan_name(self):
        """
        Scan name related to given task
        """
        if self.context is None or self.context.scanner is None:
            return None

        return self.context.scanner.NAME

    def cancel(self):
        """
        Cancels tasks. If task is already executing stop it
        """
        log.debug('Cancelling task %s', self)

        if self.executor is not None:
            log.debug('Task %s is already processing. Stopping it', self)
            self._stop()

        self._cancelled = True
        self.finish_time = time.time()

    def _stop(self):
        """
        Stop executing task
        """
        self.executor.stop()

    def kill(self):
        """
        Kill task, by default do nothing
        """
        pass

    def clear(self):
        """
        Clear after task. By default task doesn't require any special clearing,
        some task (especially which uses external tools) can need it

        """
        self.executor = None

    def has_finished(self):
        """
        Checks if task finished
        """
        return self.finish_time is not None

    @property
    def scan(self):
        """
        Scanner Scan
        """
        return self.context.scanner.scan

    def filter_out_vulnerability(self, vuln):
        """
        Filter out vulnerabilities. Some task could be executed multiple times, so found vulnrabilities need validation
        against already found vulnerabilities. Default behavior is to do nothing.
        """
        return vuln
