"""
This module contains class responsible scanning tasks.

"""
import logging as log
import time
from functools import partial

from tornado.locks import Event

from croniter import croniter
from netaddr import IPSet

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import ScanType, ScanStatus, ScanContext, Service, Scan
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
        self._aucote = aucote
        self.context = None
        self.scan = Scan(protocol=self.PROTOCOL, scanner=self.NAME, init=False)
        self._shutdown_condition = Event()
        self.status = ScanStatus.IDLE
        self.run_now = False

    @property
    def aucote(self):
        return self._aucote

    def _init(self):
        if self.context is not None:
            raise Exception("Scan context already exists")
        self.context = ScanContext(aucote=self.aucote, scanner=self)

    async def __call__(self):
        try:
            self._init()

            if not cfg['portdetection.{name}.scan_enabled'.format(name=self.NAME)]:
                log.info("Scanner %s is disabled", self.NAME)
                return
            log.info("Starting %s scanner", self.NAME)

            result = await self.run()

            run_after = cfg['portdetection.{name}.run_after'.format(name=self.NAME)]
            for scan_name in run_after:

                scan_task = self.aucote.async_task_manager.crontab_task(scan_name)
                if scan_task is not None:
                    self.aucote.ioloop.add_callback(partial(scan_task, run_now=True))

            return result
        finally:
            self.context.end = time.time()
            self.context = None
            self.expire_vulnerabilities()

    async def run(self):
        raise NotImplementedError()

    @property
    def shutdown_condition(self):
        """
        Event which is set when no scan in progress

        Returns:
            Event

        """
        return self._shutdown_condition

    async def _get_nodes_for_scanning(self, timestamp=None, filter_out_storage=True):
        """
        Get nodes for scan since timestamp.
            - If timestamp is None, it is equal: current timestamp - node scan period
            - Restrict nodes to allowed networks

        Args:
            timestamp (float):

        Returns:
            list

        """
        nodes = {
            'snmp': await self.topdis.get_snmp_nodes()
        }
        nodes['hosts'] = await self.topdis.get_all_nodes() - nodes['snmp']

        if filter_out_storage:
            storage_nodes = set(self.storage.get_nodes(
                pasttime=self._scan_interval(),
                timestamp=timestamp,
                scan=self.scan
            ))

            nodes['hosts'] = nodes['hosts'] - storage_nodes
            nodes['snmp'] = nodes['snmp'] - storage_nodes

        include_networks = self._get_networks_list()
        exclude_networks = self._get_excluded_networks_list()

        return_value = []

        if cfg['portdetection.{name}.scan_devices.snmp'.format(name=self.NAME)]:
            return_value.extend(node for node in list(nodes['snmp'])
                                if node.ip.exploded in include_networks and node.ip.exploded not in exclude_networks)

        if cfg['portdetection.{name}.scan_devices.host'.format(name=self.NAME)]:
            return_value.extend(node for node in list(nodes['hosts'])
                                if node.ip.exploded in include_networks and node.ip.exploded not in exclude_networks)

        return return_value

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

        if self.scan.start:
            previous_scan_start = current_status['scan_start']
            if previous_scan_start != self.scan.start:
                data['portdetection'][self.NAME]['status']['previous_scan_start'] = previous_scan_start
                data['portdetection'][self.NAME]['status']['scan_start'] = self.scan.start

        if status is not None:
            current_status_code = current_status['code']
            if current_status_code != status.value:
                data['portdetection'][self.NAME]['status']['code'] = status.value

        if status is ScanStatus.IDLE and self.scan.start is not None:
            data['portdetection'][self.NAME]['status']['previous_scan_duration'] = int(time.time() - self.scan.start)

        if data['portdetection'][self.NAME]['status']:
            log.debug("Update toucan by %s with %s", self.NAME, data)
            await cfg.toucan.async_push_config(data, overwrite=True, keep_history=False)

    @property
    def topdis(self):
        """
        Topdis API object

        Returns:
            Topdis

        """
        return self.aucote.topdis

    async def stop(self):
        """
        Stops scan by stopping/cancelling all its related tasks

        """
        log.info('Stopping scan %s', self.NAME)
        if self.context is None:
            log.warning("There is no %s scan in progress", self.NAME)
            return
        
        self.context.cancel()

        if not self.context.is_scan_end():
            tasks = self.context.unfinished_tasks()

            log.warning('Cancelling %s tasks for scan %s', len(tasks), self.NAME)
            for task in tasks:
                task.cancel()

        await self.context.wait_on_scan_end()

        log.info('Scan %s cancelled successfully', self.NAME)

    def prepare_vulnerability_for_kudu(self, vuln: 'Vulnerability'):
        """
        Update vulnerability to meet all fields required by kudu serializer

        """
        data = self.storage.portdetection_vulns(vuln)

        os_service = Service(name=data['os_name'], version=data['os_version'], cpe=data['os_cpe'])
        vuln.port.node.os = os_service
        vuln.port.protocol = data['protocol']
        vuln.port.banner = data['banner']
        vuln.port.service.name = data['name']
        vuln.port.service.version = data['version']
        vuln.port.service.cpe = data['cpe']

        return vuln

    def expire_vulnerabilities(self):
        """
        Update validation time of vulnerabilites

        """
        vulns = self.storage.expire_vulnerabilities()
        for vuln in vulns:
            # There is some mismatch between kudu and local storage
            if vuln.exploit.id == 0 and vuln.subid > 0:
                continue
            self.prepare_vulnerability_for_kudu(vuln)
            self.store_vulnerability(vuln)

    def store_vulnerability(self, vuln):
        """
        Saves vulnerability into database: kudu and local storage
        """
        expiration_period = parse_period(cfg['portdetection.expiration_period'])

        log.debug('Found vulnerability %s for %s', vuln.exploit.id if vuln.exploit is not None else None, vuln.port)

        try:
            # Do not save vulnerability which is already saved: FixMe: better save and update vulns
            if vuln.expiration_time is None:
                self.aucote.storage.save_vulnerabilities(vulnerabilities=[vuln], scan=self.scan)
        except Exception:
            log.warning('Error during saving vulnerability (%s, %s) to the storage',
                        vuln.exploit.id if vuln.exploit is not None else None, vuln.subid)

        # FixMe: A little bit hacking here: Serializer doesn't have access to Toucan,
        # so I have to set expiration time in vuln. Future solution: Incorporate serializer into Aucote instance

        if vuln.expiration_time is None:
            vuln.expiration_time = vuln.time + expiration_period

        msg = Serializer.serialize_vulnerability(vuln)
        self.aucote.kudu_queue.send_msg(msg)
