"""
This module contains class responsible for scanning.

"""
import ipaddress
import json
import sched
from threading import Thread, Lock
from urllib.error import URLError
import urllib.request as http
import logging as log
import time
import netifaces

from croniter import croniter
from netaddr import IPSet

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node, Scan, PhysicalPort
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
from utils.time import parse_period, parse_time_to_timestamp


class ScanThread(Thread):
    """
    Class responsible for scanning

    """

    def __init__(self, aucote, as_service=True):
        super(ScanThread, self).__init__()
        self.scheduler = sched.scheduler(time.time)
        self.as_service = as_service
        self._current_scan = []
        self.name = "Scanner"
        self.aucote = aucote
        self._lock = Lock()

        try:
            self.cron = croniter(cfg.get('service.scans.cron'), time.time())
        except KeyError:
            log.error("Please configure service.scans.cron")
            exit(1)

        self.keep_update_cron = croniter('* * * * *', time.time())

    def run_periodically(self):
        """
        Periodically runs scanning. Function is recurrence.

        Returns:
            None

        """
        self.scheduler.enterabs(next(self.cron), 1, self.run_periodically)
        self.run_scan()

    def run_scan(self):
        """
        Run scanning.

        Returns:
            None

        """
        scanner_ipv4 = MasscanPorts()
        scanner_ipv6 = PortsScan()

        nodes = [node for node in self._get_nodes_for_scanning() if node.ip.exploded in self._get_networks_list()]
        self.current_scan = nodes

        if not nodes:
            log.warning("List of nodes is empty")
            return

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (IPv4: %s, IPv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        log.info("Scanning %i IPv4 nodes for open ports.", len(nodes_ipv4))
        ports = scanner_ipv4.scan_ports(nodes_ipv4)

        log.info("Scanning %i IPv6 nodes for open ports.", len(nodes_ipv6))
        ports.extend(scanner_ipv6.scan_ports(nodes_ipv6))

        self.storage.save_nodes(nodes)

        if cfg.get('service.scans.physical'):
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addr = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addr:
                    continue

                port = PhysicalPort()
                port.interface = interface
                port.scan = Scan(start=time.time())
                ports.append(port)

        self.aucote.add_task(Executor(aucote=self.aucote, nodes=ports))
        self.current_scan = []

    def run(self):
        log.debug("Starting scanner")
        if self.as_service:
            self.scheduler.enterabs(next(self.cron), 1, self.run_periodically)
            self.scheduler.enterabs(next(self.keep_update_cron), 1, self.keep_update)
        else:
            self.run_scan()
        self.scheduler.run()

    @classmethod
    def _get_nodes(cls):
        """
        Get nodes from todis application

        """
        url = 'http://%s:%s/api/v1/nodes?ip=t' % (cfg.get('topdis.api.host'), cfg.get('topdis.api.port'))
        try:
            resource = http.urlopen(url)
        except URLError:
            log.exception('Cannot connect to topdis: %s:%s', cfg.get('topdis.api.host'), cfg.get('topdis.api.port'))
            return []

        charset = resource.headers.get_content_charset() or 'utf-8'
        nodes_txt = resource.read().decode(charset)
        nodes_cfg = json.loads(nodes_txt)

        timestamp = parse_time_to_timestamp(nodes_cfg['meta']['requestTime'])
        log.debug('Got nodes: %s', nodes_cfg)
        nodes = []
        for node_struct in nodes_cfg['nodes']:
            for node_ip in node_struct['ips']:
                node = Node(ip=ipaddress.ip_address(node_ip), node_id=node_struct['id'])
                node.name = node_struct['displayName']
                node.scan = Scan(start=timestamp)
                nodes.append(node)

        return nodes

    def _get_nodes_for_scanning(self):
        """
        Returns:
            list of nodes to be scan

        """
        topdis_nodes = self._get_nodes()

        log.info('Found %i nodes total', len(topdis_nodes))

        storage_nodes = self.storage.get_nodes(parse_period(cfg.get('service.scans.node_period')))

        for node in storage_nodes:
            try:
                topdis_nodes.remove(node)
            except ValueError:
                continue

        return topdis_nodes

    @classmethod
    def _get_networks_list(cls):
        """
        Returns list of networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg.get('service.scans.networks').cfg)
        except KeyError:
            log.error("Please set service.scans.networks in configuration file!")
            exit()

    def disable_scan(self):
        """
        Disable all future scans and cron updaters

        Returns:
            None

        """
        for task in self.scheduler.queue:
            self.scheduler.cancel(task)

    def keep_update(self):
        """
        Keeps cron update every minnute

        Returns:
            None

        """
        self.scheduler.enterabs(next(self.keep_update_cron), 1, self.keep_update)

        if int(time.monotonic() % 600) == 0:
            log.debug("keep cron update")

    def stop(self):
        """
        Stop thread.

        Returns:
            None

        """
        self.disable_scan()

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
        with self._lock:
            return self._current_scan[:]

    @current_scan.setter
    def current_scan(self, val):
        with self._lock:
            self._current_scan = val

    @property
    def previous_scan(self):
        """
        Returns previous scan timestamp

        Returns:
            float

        """
        return croniter(cfg.get('service.scans.cron'), time.time()).get_prev()

    @property
    def tasks(self):
        """
        List of tasks in scheduler

        Returns:
            list

        """
        with self._lock:
            return self.scheduler.queue[:]
