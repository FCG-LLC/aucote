"""
This module contains class responsible for scanning.

"""
import ipaddress
import json
import sched
from datetime import datetime
from urllib.error import URLError
import urllib.request as http
import logging as log
import time
import netifaces

from croniter import croniter
from netaddr import IPSet
from pylint.reporters.ureports import nodes

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node, Port, Scan
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
from utils.exceptions import TopdisConnectionException
from utils.task import Task
from utils.time import parse_period


class ScanTask(Task):
    """
    Class responsible for scanning

    """

    def __init__(self, nodes=None, as_service=True, *args, **kwargs):
        super(ScanTask, self).__init__(*args, **kwargs)
        self.nodes = nodes or self._get_nodes()
        self.scheduler = sched.scheduler(time.time)
        self.storage = self.executor.storage
        self.as_service = as_service
        self.scan = None

        try:
            self.cron = croniter(cfg.get('service.scans.cron'), time.time())
        except KeyError:
            log.error("Please configure service.scans.cron")
            exit(1)

    def run_periodically(self):
        """
        Periodically runs scanning. Function is recurrence.

        Returns:
            None

        """
        self.scheduler.enterabs(next(self.cron), 1, self.run_periodically)
        self.run()

    def run(self):
        """
        Run scanning.

        Returns:
            None

        """
        scanner_ipv4 = MasscanPorts()
        scanner_ipv6 = PortsScan()

        nodes = [node for node in self._get_nodes_for_scanning() if node.ip.exploded in self._get_networks_list()]

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (ipv4: %s, ipv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        if not nodes:
            return

        ports = scanner_ipv4.scan_ports(nodes_ipv4)
        ports.extend(scanner_ipv6.scan_ports(nodes_ipv6))

        self.storage.save_nodes(nodes)

        if cfg.get('service.scans.physical'):
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addr = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addr:
                    continue

                port = Port.physical()
                port.interface = interface
                port.scan = self.scan
                ports.append(port)

        self.executor.add_task(Executor(aucote=self.executor, nodes=ports))

    def __call__(self, *args, **kwargs):
        if self.as_service:
            self.scheduler.enterabs(next(self.cron), 1, self.run_periodically)
        else:
            self.run()
        self.scheduler.run()

    def _get_nodes(self):
        """
        Get nodes from todis application

        """
        url = 'http://%s:%s/api/v1/nodes?ip=t' % (cfg.get('topdis.api.host'), cfg.get('topdis.api.port'))
        try:
            resource = http.urlopen(url)
        except URLError:
            log.error('Cannot connect to topdis: %s:%s', cfg.get('topdis.api.host'), cfg.get('topdis.api.port'))
            raise TopdisConnectionException

        charset = resource.headers.get_content_charset() or 'utf-8'
        nodes_txt = resource.read().decode(charset)
        nodes_cfg = json.loads(nodes_txt)
        log.debug('Got nodes: %s', nodes_cfg)
        nodes = []
        for node_struct in nodes_cfg['nodes']:
            for node_ip in node_struct['ips']:
                node = Node(ip=ipaddress.ip_address(node_ip), node_id=node_struct['id'])
                node.name = node_struct['displayName']
                nodes.append(node)

        datestring = nodes_cfg['meta']['requestTime']
        timestamp = datetime.strptime(datestring[:-3] + datestring[-2:], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()

        self.scan = Scan(start=timestamp)
        return nodes

    def _get_nodes_for_scanning(self):
        """
        Returns:
            list of nodes to be scan

        """
        topdis_nodes = ScanTask._get_nodes()

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
