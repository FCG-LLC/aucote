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
            periods = cfg.get('tools.{0}.periods.*'.format(app)).cfg

            scans = self.storage.get_security_scan_info(port=port, app=app, scan=self._scan)

            for scan in scans:
                period = parse_period(periods.get(scan.exploit.name, None) or
                                      cfg.get('tools.{0}.period'.format(app)))

                if (scan.scan_end or 0) + period > time.time() and scan.exploit in exploits:
                    log.debug('Omitting %s due to recent scan (%s)', scan.exploit, scan.scan_end)
                    exploits.remove(scan.exploit)

            if not isinstance(port, SpecialPort):
                exploits = self._filter_exploits(app, exploits, port.node)

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
            exploits = self._filter_exploits(app, exploits, node)

            log.info("Using %i exploits against %s", len(exploits), node)

            task = EXECUTOR_CONFIG['apps'][app]['class'](aucote=self._aucote, exploits=exploits, node=node,
                                                         config=EXECUTOR_CONFIG['apps'][app], scan=self._scan)

            self._aucote.add_async_task(task)

    def _filter_exploits(self, app, exploits, node):
        return [exploit for exploit in exploits if self._is_exploit_allowed(exploit=exploit, app=app, node=node)]

    def _is_exploit_allowed(self, exploit, app, node):
        script_networks = cfg.get('tools.{0}.script_networks.*'.format(app)).cfg
        app_networks = cfg.get('tools.{0}.networks'.format(app)).cfg or None
        categories = {ExploitCategory[cat.upper()] for cat in cfg.get('portdetection._internal.categories').cfg}
        if not self.scanner.is_exploit_allowed(exploit):
            log.debug("Exploit %s is not allowed by scanner (%s) configuration", str(exploit), self.scanner.NAME)
            return False

        if exploit.categories - categories:
            log.debug("Exploit %s is not allowed by categories configuration", str(exploit))
            return False

        networks = script_networks.get(exploit.name, None)

        if networks is None:
            networks = app_networks

        if networks is not None and node.ip.exploded not in IPSet(networks):
            log.debug("Exploit %s is not allowed by networks (%s) configuration", str(exploit), networks)
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
