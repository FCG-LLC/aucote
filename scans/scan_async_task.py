"""
This module contains class responsible for scanning.

"""
import ipaddress
from functools import partial
from urllib.error import URLError
import urllib.request as http
import logging as log
import time
from threading import Lock
import ujson as json
import netifaces

from croniter import croniter
from netaddr import IPSet
from tornado import gen
from tornado.ioloop import IOLoop

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node, Scan, PhysicalPort, ScanStatus, TopisOSDiscoveryType, Service, CPEType
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
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
        self.scan_start = None

        try:
            self.aucote.async_task_manager.add_crontab_task(self._scan, cfg['portdetection.scan_cron'])
            self.aucote.async_task_manager.add_crontab_task(self._run_tools, cfg['portdetection.tools_cron'])
        except KeyError:
            log.error("Please configure portdetection.scan_cron and portdetection.tools_cron")
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

    @gen.coroutine
    def _scan(self):
        """
        Scan nodes for open ports

        Returns:
            None

        """
        if not cfg['portdetection.scan_enable']:
            return
        log.info("Starting port scan")
        nodes = self._get_nodes_for_scanning(timestamp=None)
        log.debug("Found %i nodes for potential scanning", len(nodes))
        yield self.run_scan(nodes, scan_only=True)

    @gen.coroutine
    def _run_tools(self):
        """
        Run scan by using tools and historical port data

        Returns:
            None

        """
        log.info("Starting security scan")
        nodes = self._get_topdis_nodes()
        ports = self.get_ports_for_script_scan(nodes)
        log.debug("Ports for security scan: %s", ports)
        self.aucote.add_task(Executor(aucote=self.aucote, ports=ports))

    @gen.coroutine
    def run_scan(self, nodes, scan_only=False):
        """
        Run scanning.

        Returns:
            None

        """
        self.scan_start = time.time()
        self.update_scan_status(ScanStatus.IN_PROGRESS)

        nmap_udp = cfg['portdetection.nmap_udp']

        self.current_scan = nodes

        if not nodes:
            log.warning("List of nodes is empty")
            self._clean_scan()
            return

        self.storage.save_nodes(nodes)

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (IPv4: %s, IPv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        log.info("Scanning %i IPv4 nodes for open ports.", len(nodes_ipv4))
        scanner_ipv4 = MasscanPorts(udp=not nmap_udp)
        ports = yield scanner_ipv4.scan_ports(nodes_ipv4)

        log.info("Scanning %i IPv6 nodes for open ports.", len(nodes_ipv6))
        scanner_ipv6 = PortsScan(ipv6=True, tcp=True, udp=True)
        ports_ipv6 = yield scanner_ipv6.scan_ports(nodes_ipv6)
        ports.extend(ports_ipv6)

        if nmap_udp:
            log.info("Scanning %i IPv4 nodes for open UDP ports.", len(nodes_ipv4))
            scanner_ipv4_udp = PortsScan(ipv6=False, tcp=False, udp=True)
            ports_udp = yield scanner_ipv4_udp.scan_ports(nodes_ipv4)
            ports.extend(ports_udp)

        port_range_allow = NmapTool.parse_nmap_ports(cfg['portdetection.ports.include'])
        port_range_deny = NmapTool.parse_nmap_ports(cfg['portdetection.ports.exclude'])

        ports = [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]

        if cfg['service.scans.physical']:
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addr = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addr:
                    continue

                port = PhysicalPort()
                port.interface = interface
                port.scan = Scan(start=time.time())
                ports.append(port)

        self.aucote.add_task(Executor(aucote=self.aucote, ports=ports, scan_only=scan_only))
        self.current_scan = []

        self._clean_scan()

    def _clean_scan(self):
        """
        Clean scan and update scan status

        Returns:
            None

        """
        self.update_scan_status(ScanStatus.IDLE)

        if not self.as_service:
            IOLoop.current().stop()

    @classmethod
    def _get_topdis_nodes(cls):
        """
        Get nodes from todis application

        """
        url = 'http://%s:%s/api/v1/nodes?ip=t' % (cfg['topdis.api.host'], cfg['topdis.api.port'])
        try:
            resource = http.urlopen(url)
        except URLError:
            log.exception('Cannot connect to topdis: %s:%s', cfg['topdis.api.host'], cfg['topdis.api.port'])
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

                software = node_struct.get('software', {})
                os = software.get('os', {})

                if os.get('discoveryType') in (TopisOSDiscoveryType.DIRECT.value,):
                    node.os.name, node.os.version = os.get('name'), os.get('version')

                    if " " in node.os.version:
                        log.warning("Currently doesn't support space in OS Version for cpe")
                    else:
                        node.os.cpe = Service.build_cpe(product=node.os.name, version=node.os.version, type=CPEType.OS)

                nodes.append(node)

        log.debug('Got %i nodes from topdis', len(nodes))
        return nodes

    def _get_nodes_for_scanning(self, timestamp=None):
        """
        Get nodes for scan since timestamp.
            - If timestamp is None, it is equal: current timestamp - node scan period
            - Restrict nodes to allowed networks

        Args:
            timestamp (float):

        Returns:
            list

        """
        topdis_nodes = self._get_topdis_nodes()

        storage_nodes = self.storage.get_nodes(parse_period(cfg['portdetection.scan_interval']), timestamp=timestamp)

        nodes = list(set(topdis_nodes) - set(storage_nodes))

        include_networks = self._get_networks_list()
        exclude_networks = self._get_excluded_networks_list()

        return [node for node in nodes if node.ip.exploded in include_networks
                and node.ip.exploded not in exclude_networks]

    @classmethod
    def _get_networks_list(cls):
        """
        Returns list of networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg['portdetection.networks.include'])
        except KeyError:
            log.error("Please set portdetection.networks.include in configuration file!")
            exit()

    @classmethod
    def _get_excluded_networks_list(cls):
        """
        List of excluded networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg['portdetection.networks.exclude'])
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

        return croniter(cfg['portdetection.scan_cron'], time.time()).get_prev()

    @property
    def previous_tool_scan(self):
        """
        Previous tool scan timestamp

        Returns:
            float

        """
        return croniter(cfg['portdetection.tools_cron'], time.time()).get_prev()

    def get_ports_for_script_scan(self, nodes):
        """
        Get ports for scanning. Topdis node data combined with stored open ports data.

        Returns:
            list

        """
        return self.storage.get_ports_by_nodes(nodes=nodes, timestamp=self.previous_tool_scan)

    @property
    def next_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return croniter(cfg['portdetection.scan_cron'], time.time()).get_next()

    @property
    def next_tool_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return croniter(cfg['portdetection.tools_cron'], time.time()).get_next()

    def update_scan_status(self, status):
        """
        Update scan status base on status value

        Args:
            status (ScanStatus):

        Returns:
            None

        """
        if not cfg.toucan:
            return

        data = {
            'previous_scan': self.previous_scan,
            'next_scan': self.next_scan,
            'scan_start': self.scan_start,
            'scan_duration': None,
            'status': status.value
        }

        if status is ScanStatus.IDLE:
            data['scan_duration'] = time.time() - self.scan_start

        cfg.toucan.put('portdetection.status', data)
