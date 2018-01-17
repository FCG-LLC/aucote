"""
Class responsible for mapping scans and port, service

"""
import time
import logging as log

from netaddr import IPSet

from aucote_cfg import cfg
from fixtures.exploits.exploit import ExploitCategory
from scans.executor_config import EXECUTOR_CONFIG
from structs import SpecialPort
from utils.time import parse_period


class TaskMapper(object):
    """
    Assign tasks for a provided port

    """

    def __init__(self, aucote, scan, scanner):
        """
        Args:
            executor (Executor): tasks executor
            scan (Scan): Scan under which the mapper is working

        """
        self._aucote = aucote
        self._scan = scan
        self.scanner = scanner

    async def assign_tasks(self, port, scripts=None):
        """

        Args:
            port (Port):
            scripts (list|None): list of exploits or None, which stands for all exploits

        Returns:

        """
        scripts = scripts or self._aucote.exploits.find_all_matching(port)

        for app, exploits in scripts.items():
            if not cfg['tools.{0}.enable'.format(app)]:
                continue

            log.info("Found %i exploits (%s) for %s", len(exploits), app, port)

            if not isinstance(port, SpecialPort):
                exploits = self._filter_exploits(exploits)

            log.info("Using %i exploits against %s", len(exploits), port)
            self.store_security_scan(port=port, exploits=exploits)
            task = EXECUTOR_CONFIG['apps'][app]['class'](aucote=self._aucote, exploits=exploits, port=port.copy(),
                                                         config=EXECUTOR_CONFIG['apps'][app], scan=self._scan)

            self._aucote.add_async_task(task)

    async def assign_tasks_for_node(self, node):
        """
        Assign tasks for provided node
        Args:
            node:
        Returns:
            None
        """
        apps = EXECUTOR_CONFIG['node_scan']
        scripts = self._aucote.exploits.find_by_apps(apps)

        for app, exploits in scripts.items():
            exploits = self._filter_exploits(exploits)

            log.info("Using %i exploits against %s", len(exploits), node)

            task = EXECUTOR_CONFIG['apps'][app]['class'](aucote=self._aucote, exploits=exploits, node=node,
                                                         config=EXECUTOR_CONFIG['apps'][app], scan=self._scan)

            self._aucote.add_async_task(task)

    def _filter_exploits(self, exploits):
        return [exploit for exploit in exploits if self._is_exploit_allowed(exploit=exploit)]

    def _is_exploit_allowed(self, exploit):
        categories = {ExploitCategory[cat.upper()] for cat in cfg.get('portdetection._internal.categories').cfg}
        if not self.scanner.is_exploit_allowed(exploit):
            log.debug("Exploit %s is not allowed by scanner (%s) configuration", str(exploit), self.scanner.NAME)
            return False

        if exploit.categories - categories:
            log.debug("Exploit %s is not allowed by categories configuration", str(exploit))
            return False

        return True

    @property
    def exploits(self):
        """
        Executor's exploits

        """
        return self._aucote.exploits

    def store_security_scan(self, port, exploits):
        """
        Saves scan details into storage

        Args:
            port (Port):
            exploits (Exploits):

        Returns:
            None
        """
        self.storage.save_security_scans(exploits=exploits, port=port, scan=self._scan)

    @property
    def storage(self):
        """
        Aucote's storage

        Returns:
            Storage

        """
        return self._aucote.storage
