"""
This module contains class responsible for scanning.

"""
import ipaddress
import json
import sched
from urllib.error import URLError
import urllib.request as http
import logging as log
import time
import netifaces

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node, Port
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
        self.scan_period = parse_period(cfg.get('service.scans.period'))
        self.storage = self.executor.storage
        self.as_service = as_service

    def run_periodically(self):
        """
        Periodically runs scanning. Function is recurrence.

        Returns:
            None

        """
        self.scheduler.enter(self.scan_period, 1, self.run_periodically)
        self.run()

    def run(self):
        """
        Run scanning.

        Returns:
            None

        """
        scanner_ipv4 = MasscanPorts()
        scanner_ipv6 = PortsScan()

        nodes = self._get_nodes_for_scanning()

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (ipv4: %s, ipv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        if not nodes:
            return

        ports = scanner_ipv4.scan_ports(nodes_ipv4)
        ports.extend(scanner_ipv6.scan_ports(nodes_ipv6))

        self.storage.save_nodes(nodes)

        interfaces = netifaces.interfaces()

        for interface in interfaces:
            addr = netifaces.ifaddresses(interface)
            if netifaces.AF_INET not in addr:
                continue

            port = Port.physical()
            port.interface = interface
            ports.append(port)

        self.executor.add_task(Executor(aucote=self.executor, nodes=ports))

    def __call__(self, *args, **kwargs):
        if self.as_service:
            self.run_periodically()
        else:
            self.run()
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
