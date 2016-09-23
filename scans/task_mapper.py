"""make install
Class responsible for mapping scans and port, service

"""
import time
import logging as log

from aucote_cfg import cfg
from scans.executor_config import EXECUTOR_CONFIG
from utils.time import parse_period


class TaskMapper:
    """
    Assign tasks for a provided port

    """

    def __init__(self, executor):
        """
        Args:
            executor (Executor): tasks executor

        """
        self._executor = executor

    def assign_tasks(self, port, storage):
        """
        Assign tasks for a provided port

        """

        scripts = self._executor.exploits.find_all_matching(port)

        for app, exploits in scripts.items():
            if not cfg.get('tools.{0}.enable'.format(app)):
                continue

            log.debug("Found %i exploits", len(exploits))

            try:
                periods = cfg.get('tools.{0}.periods'.format(app)).cfg
            except KeyError:
                periods = {}
                log.info("Cannot find periods configuration for %s. Using default.", app)

            scans = storage.get_scan_info(port=port, app=app)

            for scan in scans:
                period = parse_period(periods.get(scan['exploit_name'], None) or
                                      cfg.get('tools.{0}.period'.format(app)))

                if scan['scan_end'] + period > time.time():
                    exploits.remove(scan['exploit'])

            log.debug("Using %i exploits", len(exploits))
            self.store_scan_details(port=port, exploits=exploits, storage=storage)
            task = EXECUTOR_CONFIG['apps'][app]['class'](executor=self._executor, exploits=exploits, port=port,
                                                         config=EXECUTOR_CONFIG['apps'][app])

            self.executor.add_task(task)

    @property
    def executor(self):
        """
        Returns: Executor

        """
        return self._executor

    @property
    def exploits(self):
        """
        Executor's exploits

        """
        return self._executor.exploits

    @classmethod
    def store_scan_details(cls, port, exploits, storage):
        """
        Saves scan details into storage

        Args:
            port (Port):
            exploits (Exploits):
            storage (Storage):

        Returns:
            None
        """
        for exploit in exploits:
            storage.save_scan(exploit=exploit, port=port, scan_start=port.scan.start)
