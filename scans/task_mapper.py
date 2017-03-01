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

    def assign_tasks(self, port, storage):
        """
        Assign tasks for a provided port

        """
        scripts = self._aucote.exploits.find_all_matching(port)

        for app, exploits in scripts.items():
            if not cfg.get('tools.{0}.enable'.format(app)):
                continue

            log.info("Found %i exploits", len(exploits))

            try:  # TODO: Move it to Tucan once it is ready.
                periods = cfg.get('tools.{0}.periods.*'.format(app)).cfg
            except KeyError:
                periods = {}
                log.info("Cannot find periods configuration for %s. Using default.", app)

            scans = storage.get_scan_info(port=port, app=app)

            for scan in scans:
                period = parse_period(periods.get(scan['exploit_name'], None) or
                                      cfg.get('tools.{0}.period'.format(app)))

                if scan['scan_end'] + period > time.time() and scan['exploit'] in exploits:
                    exploits.remove(scan['exploit'])

            if not isinstance(port, SpecialPort):
                try:  # TODO: Move it to Tucan once it is ready.
                    script_networks = cfg.get('tools.{0}.script_networks.*'.format(app)).cfg
                except KeyError:
                    script_networks = {}

                try:  # TODO: Move it to Tucan once it is ready.
                    app_networks = cfg.get('tools.{0}.networks'.format(app)).cfg
                except KeyError:
                    app_networks = None

                for exploit in reversed(exploits):
                    networks = script_networks.get(exploit.name, None)

                    if networks is None:
                        networks = app_networks

                    if networks is not None and port.node.ip.exploded not in IPSet(networks):
                        exploits.remove(exploit)

            log.info("Using %i exploits against %s", len(exploits), port)
            self.store_scan_details(port=port, exploits=exploits, storage=storage)
            task = EXECUTOR_CONFIG['apps'][app]['class'](aucote=self._aucote, exploits=exploits, port=port.copy(),
                                                         config=EXECUTOR_CONFIG['apps'][app])

            self._aucote.add_task(task)

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
