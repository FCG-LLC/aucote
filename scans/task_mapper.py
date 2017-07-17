"""make install
Class responsible for mapping scans and port, service

"""
import time
import logging as log

from netaddr import IPSet

from aucote_cfg import cfg
from scans.executor_config import EXECUTOR_CONFIG
from structs import SpecialPort
from utils.time import parse_period


class TaskMapper:
    """
    Assign tasks for a provided port

    """

    def __init__(self, aucote):
        """
        Args:
            executor (Executor): tasks executor

        """
        self._aucote = aucote

    async def assign_tasks(self, port, storage):
        """
        Assign tasks for a provided port

        """
        scripts = self._aucote.exploits.find_all_matching(port)

        for app, exploits in scripts.items():
            if not cfg['tools.{0}.enable'.format(app)]:
                continue

            log.info("Found %i exploits", len(exploits))
            periods = cfg.get('tools.{0}.periods.*'.format(app)).cfg

            scans = storage.get_scan_info(port=port, app=app)

            for scan in scans:
                period = parse_period(periods.get(scan['exploit_name'], None) or
                                      cfg.get('tools.{0}.period'.format(app)))

                if scan['scan_end'] + period > time.time() and scan['exploit'] in exploits:
                    exploits.remove(scan['exploit'])

            if not isinstance(port, SpecialPort):
                exploits = self._filter_exploits(app, exploits, port.node)

            log.info("Using %i exploits against %s", len(exploits), port)
            self.store_scan_details(port=port, exploits=exploits, storage=storage)
            task = EXECUTOR_CONFIG['apps'][app]['class'](aucote=self._aucote, exploits=exploits, port=port.copy(),
                                                         config=EXECUTOR_CONFIG['apps'][app])

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
                                                         config=EXECUTOR_CONFIG['apps'][app])

            self._aucote.add_async_task(task)

    def _filter_exploits(self, app, exploits, node):
        return [exploit for exploit in exploits if self._is_exploit_allowed(exploit=exploit, app=app, node=node)]

    @staticmethod
    def _is_exploit_allowed(exploit, app, node):
        script_networks = cfg.get('tools.{0}.script_networks.*'.format(app)).cfg
        app_networks = cfg.get('tools.{0}.networks'.format(app)).cfg or None

        networks = script_networks.get(exploit.name, None)

        if networks is None:
            networks = app_networks

        if networks is not None and node.ip.exploded not in IPSet(networks):
            return False
        return True

    @property
    def exploits(self):
        """
        Executor's exploits

        """
        return self._aucote.exploits

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
        storage.save_scans(exploits=exploits, port=port)
