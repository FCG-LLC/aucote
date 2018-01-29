"""
This module contains class responsible scanning tasks.

"""
import logging as log
import time
from tornado.locks import Event

from croniter import croniter
from netaddr import IPSet

from aucote_cfg import cfg
from structs import ScanType, ScanStatus, ScanContext
from utils.time import parse_period


class ScanAsyncTask(object):
    """
    Parent class for all scanning tasks

    """
    LIVE_SCAN_CRON = '* * * * *'
    PROTOCOL = None
    NAME = None

    TOPDIS_MIN_TIME = 5
    TOPDIS_MAX_TIME = 30
    TOPDIS_RETRIES = 5

    def __init__(self, aucote):
        self._current_scan = []
        self.context = ScanContext(aucote=aucote, scan=self)
        self.scan_start = None
        self._shutdown_condition = Event()
        self.status = ScanStatus.IDLE
        self.run_now = False

    @property
    def aucote(self):
        return self.context.aucote

    async def __call__(self, *args, **kwargs):
        if not cfg['portdetection.{name}.scan_enabled'.format(name=self.NAME)]:
            log.info("Scanner %s is disabled", self.NAME)
            return
        log.info("Starting %s scanner", self.NAME)

        result = await self.run()

        run_after = cfg['portdetection.{name}.run_after'.format(name=self.NAME)]
        for scan_name in run_after:

            scan_task = self.aucote.async_task_manager.cron_task(scan_name)
            if scan_task is not None:
                scan_task.run_asap()

        return result

    async def run(self):
        raise NotImplementedError()

    def run_asap(self):
        """
        Wait on finish of current scan and 'force' to run in next iteration

        """
        log.info('%s will be set to start as soon as possible', self.NAME)
        self.run_now = True

    @property
    def shutdown_condition(self):
        """
        Event which is set when no scan in progress

        Returns:
            Event

        """
        return self._shutdown_condition

    async def _get_nodes_for_scanning(self, scan, timestamp=None, filter_out_storage=True):
        """
        Get nodes for scan since timestamp.
            - If timestamp is None, it is equal: current timestamp - node scan period
            - Restrict nodes to allowed networks

        Args:
            timestamp (float):

        Returns:
            list

        """
        nodes = set(await self.topdis.get_nodes())

        if filter_out_storage:
            storage_nodes = self.storage.get_nodes(pasttime=self._scan_interval(), timestamp=timestamp, scan=scan)
            nodes = nodes - set(storage_nodes)

        include_networks = self._get_networks_list()
        exclude_networks = self._get_excluded_networks_list()

        return [node for node in list(nodes) if node.ip.exploded in include_networks
                and node.ip.exploded not in exclude_networks]

    def _get_networks_list(self):
        """
        Returns list of networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg['portdetection.{name}.networks.include'.format(name=self.NAME)])
        except KeyError:
            log.error("Please set portdetection.%s.networks.include in configuration file!", self.NAME)
            exit()

    def _get_excluded_networks_list(self):
        """
        List of excluded networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg['portdetection.{name}.networks.exclude'.format(name=self.NAME)])
        except KeyError:
            return []

    @property
    def storage(self):
        """
        Handler to application storage

        Returns:
            Storage

        """
        return self.aucote.storage

    @property
    def current_scan(self):
        """
        List of currently scan nodes

        Returns:
            list

        """
        return self._current_scan[:]

    @current_scan.setter
    def current_scan(self, val):
        self._current_scan = val

    @property
    def previous_scan(self):
        """
        Returns previous scan timestamp

        Returns:
            float

        """

        return int(croniter(self._scan_cron(), time.time()).get_prev())

    @property
    def next_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return int(croniter(self._scan_cron(), time.time()).get_next())

    def _scan_interval(self):
        """
        Get interval between particular node scan

        Returns:
            int

        """
        if cfg['portdetection.{name}.scan_type'.format(name=self.NAME)] == ScanType.PERIODIC.value:
            return 0

        return parse_period(cfg['portdetection.{name}.live_scan.min_time_gap'.format(name=self.NAME)])

    def _scan_cron(self):
        """
        Get scan cron

        Returns:
            str

        """
        if cfg['portdetection.{name}.scan_type'.format(name=self.NAME)] == ScanType.LIVE.value:
            return self.LIVE_SCAN_CRON

        return cfg['portdetection.{name}.periodic_scan.cron'.format(name=self.NAME)]

    def is_exploit_allowed(self, exploit):
        """
        Check if exploit can be executed by scanner

        Args:
            exploit:

        Returns:
            bool

        """
        return exploit.id in map(int, cfg['portdetection.{0}.scripts'.format(self.NAME)])

    async def _clean_scan(self):
        """
        Clean scan and update scan status

        Returns:
            None

        """
        await self.update_scan_status(ScanStatus.IDLE)
        self._shutdown_condition.set()

    async def update_scan_status(self, status=None):
        """
        Update scan status base on status value

        Args:
            status (ScanStatus):

        Returns:
            None

        """
        self.status = status

        if not cfg.toucan or cfg['portdetection.{name}.scan_type'.format(name=self.NAME)] == ScanType.LIVE.value:
            return

        current_status = cfg.get('portdetection.{0}.status.*'.format(self.NAME), cache=False)

        data = {
            'portdetection': {
                self.NAME: {
                    'status': {
                    }
                }
            }
        }

        log.debug("Current status for %s is %s", self.NAME, current_status.cfg)
        next_scan = round(current_status['next_scan_start'])
        if next_scan != self.next_scan:
            data['portdetection'][self.NAME]['status']['next_scan_start'] = self.next_scan

        if self.scan_start:
            previous_scan_start = current_status['scan_start']
            if previous_scan_start != self.scan_start:
                data['portdetection'][self.NAME]['status']['previous_scan_start'] = previous_scan_start
                data['portdetection'][self.NAME]['status']['scan_start'] = self.scan_start

        if status is not None:
            current_status_code = current_status['code']
            if current_status_code != status.value:
                data['portdetection'][self.NAME]['status']['code'] = status.value

        if status is ScanStatus.IDLE and self.scan_start is not None:
            data['portdetection'][self.NAME]['status']['previous_scan_duration'] = int(time.time() - self.scan_start)

        if data['portdetection'][self.NAME]['status']:
            log.debug("Update toucan by %s with %s", self.NAME, data)
            await cfg.toucan.push_config(data, overwrite=True, keep_history=False)

    @property
    def topdis(self):
        """
        Topdis API object

        Returns:
            Topdis

        """
        return self.aucote.topdis
