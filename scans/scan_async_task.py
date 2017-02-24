"""
This module contains class responsible for scanning.

"""
import ipaddress
import json
from functools import partial
from urllib.error import URLError
import urllib.request as http
import logging as log
import time
import netifaces

from croniter import croniter
from netaddr import IPSet
from tornado import gen
from tornado.ioloop import IOLoop
from threading import Lock

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node, Scan, PhysicalPort
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
from utils.async_task_manager import AsyncTaskManager
from tools.nmap.tool import NmapTool
from utils.time import parse_period, parse_time_to_timestamp


class ScanAsyncTask(object):
    """
    Class responsible for scanning

    """
    def __init__(self, aucote, as_service=True):
        self.as_service = as_service
        self._current_scan = []
        self.aucote = aucote
        self._lock = Lock()

        try:
            self.aucote.async_task_manager.add_crontab_task(self._scan, cfg.get('service.scans.scan_cron'))
            self.aucote.async_task_manager.add_crontab_task(self._run_tools, cfg.get('service.scans.tools_cron'))
        except KeyError:
            log.error("Please configure service.scans.scan_cron and service.scans.tools_cron")
            exit(1)

    def run(self):
        """
        Run tasks

        Returns:
            None

        """
        log.debug("Starting cron")
        if self.as_service:
            self.aucote.async_task_manager.start()
        else:
            IOLoop.current().add_callback(partial(self.run_scan, self._get_nodes_for_scanning()))

    @AsyncTaskManager.unique_task
    @gen.coroutine
    def _scan(self):
        """
        Scan nodes for open ports

        Returns:
            None

        """
        log.info("Starting port scan")
        nodes = self._get_nodes_for_scanning(timestamp=None)
        log.debug("Found %i nodes for potential scanning", len(nodes))
        yield self.run_scan(nodes, scan_only=True)

    @AsyncTaskManager.unique_task
    @gen.coroutine
    def _run_tools(self):
        """
        Run scan by using tools and historical port data

        Returns:
            None

        """
        log.info("Starting security scan")
        ports = self.get_ports_for_script_scan()
        log.debug("Ports for security scan: %s", ports)
        self.aucote.add_task(Executor(aucote=self.aucote, nodes=ports))

    @gen.coroutine
    def run_scan(self, nodes, scan_only=False):
        """
        Run scanning.

        Returns:
            None

        """
        scanner_ipv4 = MasscanPorts()
        # scanner_ipv4_udp = PortsScan(ipv6=False, tcp=False, udp=True)
        scanner_ipv6 = PortsScan(ipv6=True, tcp=True, udp=True)

        nodes = [node for node in nodes if node.ip.exploded in self._get_networks_list()
                 and node.ip.exploded not in self._get_excluded_networks_list()]

        self.current_scan = nodes

        if not nodes:
            log.warning("List of nodes is empty")
            return

        self.storage.save_nodes(nodes)

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (IPv4: %s, IPv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        log.info("Scanning %i IPv4 nodes for open ports.", len(nodes_ipv4))
        ports = yield scanner_ipv4.scan_ports(nodes_ipv4)

        # ports_udp = yield scanner_ipv4_udp.scan_ports(nodes_ipv4)
        # ports.extend(ports_udp)

        log.info("Scanning %i IPv6 nodes for open ports.", len(nodes_ipv6))

        ports_ipv6 = yield scanner_ipv6.scan_ports(nodes_ipv6)
        ports.extend(ports_ipv6)

        port_range_allow = NmapTool.parse_nmap_ports(cfg.get('service.scans.ports.include'))
        port_range_deny = NmapTool.parse_nmap_ports(cfg.get('service.scans.ports.exclude'))

        ports = [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]

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

        self.aucote.add_task(Executor(aucote=self.aucote, nodes=ports, scan_only=scan_only))
        self.current_scan = []

        if not self.as_service:
            IOLoop.current().stop()

    @classmethod
    def _get_topdis_nodes(cls):
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
        nodes = []
        for node_struct in nodes_cfg['nodes']:
            for node_ip in node_struct['ips']:
                node = Node(ip=ipaddress.ip_address(node_ip), node_id=node_struct['id'])
                node.name = node_struct['displayName']
                node.scan = Scan(start=timestamp)
                nodes.append(node)

        log.debug('Got %i nodes from topdis: %s', len(nodes), nodes)
        return nodes

    def _get_nodes_for_scanning(self, timestamp=None):
        """
        Get nodes for scan since timestamp. If timestamp is None, it is equal: current timestamp - node scan period

        Args:
            timestamp (float):

        Returns:
            list

        """
        topdis_nodes = self._get_topdis_nodes()

        storage_nodes = self.storage.get_nodes(parse_period(cfg.get('service.scans.node_period')), timestamp=timestamp)

        return list(set(topdis_nodes) - set(storage_nodes))

    @classmethod
    def _get_networks_list(cls):
        """
        Returns list of networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg.get('service.scans.networks.include').cfg)
        except KeyError:
            log.error("Please set service.scans.networks.include in configuration file!")
            exit()


    def _get_excluded_networks_list(self):
        """
        List of excluded networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg.get('service.scans.networks.exclude').cfg)
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

        return croniter(cfg.get('service.scans.scan_cron'), time.time()).get_prev()

    @property
    def previous_tool_scan(self):
        return croniter(cfg.get('service.scans.tools_cron'), time.time()).get_prev()

    def get_ports_for_script_scan(self):
        """
        Get ports for scanning. Topdis node data combined with stored open ports data.

        Returns:
            list

        """
        return self.storage.get_ports_by_nodes(self._get_topdis_nodes(), timestamp=self.previous_tool_scan)

    @property
    def next_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return croniter(cfg.get('service.scans.scan_cron'), time.time()).get_next()

    @property
    def next_tool_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return croniter(cfg.get('service.scans.tools_cron'), time.time()).get_next()
