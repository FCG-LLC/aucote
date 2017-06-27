"""
This module contains class responsible for scanning.

"""
import ipaddress
from urllib.error import URLError
import logging as log
import time
import ujson as json
import netifaces

from croniter import croniter
from netaddr import IPSet
from tornado.locks import Event

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node, Scan, PhysicalPort, ScanStatus, ScanType, TopisOSDiscoveryType, Service, CPEType
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
from tools.nmap.tool import NmapTool
from utils.http_client import HTTPClient
from utils.time import parse_period, parse_time_to_timestamp


class ScanAsyncTask(object):
    """
    Class responsible for scanning

    """
    LIVE_SCAN_CRON = '* * * * *'

    def __init__(self, aucote, as_service=True):
        self.as_service = as_service
        self._current_scan = []
        self.aucote = aucote
        self.scan_start = None
        self._shutdown_condition = Event()

        if as_service:
            self.aucote.async_task_manager.add_crontab_task(self._scan, self._scan_cron)
            self.aucote.async_task_manager.add_crontab_task(self._run_tools, self._tools_cron)

    @property
    def shutdown_condition(self):
        """
        Event which is set when no scan in progress

        Returns:
            Event

        """
        return self._shutdown_condition

    def _tools_cron(self):
        return cfg['portdetection._internal.tools_cron']

    async def run(self):
        """
        Run tasks

        Returns:
            None

        """
        log.debug("Starting cron")
        self.aucote.async_task_manager.start()
        if not self.as_service:
            await self.run_scan(await self._get_nodes_for_scanning())

    async def _scan(self):
        """
        Scan nodes for open ports

        Returns:
            None

        """
        if not cfg['portdetection.scan_enabled']:
            return
        log.info("Starting port scan")
        nodes = await self._get_nodes_for_scanning(timestamp=None)
        log.debug("Found %i nodes for potential scanning", len(nodes))
        await self.run_scan(nodes, scan_only=True)

    async def _run_tools(self):
        """
        Run scan by using tools and historical port data

        Returns:
            None

        """
        log.info("Starting security scan")
        nodes = await self._get_topdis_nodes()
        ports = self.get_ports_for_script_scan(nodes)
        log.debug("Ports for security scan: %s", ports)
        self.aucote.add_async_task(Executor(aucote=self.aucote, ports=ports))

    async def run_scan(self, nodes, scan_only=False):
        """
        Run scanning.

        Returns:
            None

        """
        self._shutdown_condition.clear()
        self.scan_start = time.time()
        await self.update_scan_status(ScanStatus.IN_PROGRESS)

        nmap_udp = cfg['portdetection._internal.nmap_udp']

        self.current_scan = nodes

        if not nodes:
            log.warning("List of nodes is empty")
            await self._clean_scan()
            return

        self.storage.save_nodes(nodes)

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (IPv4: %s, IPv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        log.info("Scanning %i IPv4 nodes for open ports.", len(nodes_ipv4))
        scanner_ipv4 = MasscanPorts(udp=not nmap_udp)
        ports = await scanner_ipv4.scan_ports(nodes_ipv4)

        log.info("Scanning %i IPv6 nodes for open ports.", len(nodes_ipv6))
        scanner_ipv6 = PortsScan(ipv6=True, tcp=True, udp=True)
        ports_ipv6 = await scanner_ipv6.scan_ports(nodes_ipv6)
        ports.extend(ports_ipv6)

        if nmap_udp:
            log.info("Scanning %i IPv4 nodes for open UDP ports.", len(nodes_ipv4))
            scanner_ipv4_udp = PortsScan(ipv6=False, tcp=False, udp=True)
            ports_udp = await scanner_ipv4_udp.scan_ports(nodes_ipv4)
            ports.extend(ports_udp)

        port_range_allow = NmapTool.ports_from_list(tcp=cfg['portdetection.ports.tcp.include'],
                                                    udp=cfg['portdetection.ports.tcp.include'])

        port_range_deny = NmapTool.ports_from_list(tcp=cfg['portdetection.ports.tcp.exclude'],
                                                   udp=cfg['portdetection.ports.tcp.exclude'])

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

        self.aucote.add_async_task(Executor(aucote=self.aucote, ports=ports, scan_only=scan_only))
        self.current_scan = []

        await self._clean_scan()

    async def _clean_scan(self):
        """
        Clean scan and update scan status

        Returns:
            None

        """
        await self.update_scan_status(ScanStatus.IDLE)
        self._shutdown_condition.set()

        if not self.as_service:
            await self.aucote.async_task_manager.stop()

    @classmethod
    async def _get_topdis_nodes(cls):
        """
        Get nodes from todis application

        """
        url = 'http://%s:%s/api/v1/nodes?ip=t' % (cfg['topdis.api.host'], cfg['topdis.api.port'])
        try:
            resource = await HTTPClient.instance().get(url)
        except URLError:
            log.exception('Cannot connect to topdis: %s:%s', cfg['topdis.api.host'], cfg['topdis.api.port'])
            return []

        nodes_cfg = json.loads(resource.body)

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
                        log.warning("Currently doesn't support space in OS Version for cpe: '%s' for '%s'",
                                    node.os.version, node.os.name)
                    else:
                        node.os.cpe = Service.build_cpe(product=node.os.name, version=node.os.version, type=CPEType.OS)

                nodes.append(node)

        log.debug('Got %i nodes from topdis', len(nodes))
        return nodes

    async def _get_nodes_for_scanning(self, timestamp=None):
        """
        Get nodes for scan since timestamp.
            - If timestamp is None, it is equal: current timestamp - node scan period
            - Restrict nodes to allowed networks

        Args:
            timestamp (float):

        Returns:
            list

        """
        topdis_nodes = await self._get_topdis_nodes()

        storage_nodes = self.storage.get_nodes(self._scan_interval(), timestamp=timestamp)

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

        return croniter(self._scan_cron(), time.time()).get_prev()

    @property
    def previous_tool_scan(self):
        """
        Previous tool scan timestamp

        Returns:
            float

        """
        return croniter(cfg['portdetection._internal.tools_cron'], time.time()).get_prev()

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
        return croniter(self._scan_cron(), time.time()).get_next()

    @property
    def next_tool_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return croniter(cfg['portdetection._internal.tools_cron'], time.time()).get_next()

    async def update_scan_status(self, status):
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
            'portdetection': {
                'status': {
                    'previous_scan_start': self.previous_scan,
                    'next_scan_start': self.next_scan,
                    'scan_start': self.scan_start,
                    'previous_scan_duration': 0,
                    'code': status.value
                }
            }
        }

        if status is ScanStatus.IDLE:
            data['portdetection']['status']['previous_scan_duration'] = int(time.time() - self.scan_start)

        await cfg.toucan.push_config(data, overwrite=True)

    def _scan_interval(self):
        """
        Get interval between particular node scan

        Returns:
            int

        """
        if cfg['portdetection.scan_type'] == ScanType.PERIODIC.value:
            return 0

        return parse_period(cfg['portdetection.live_scan.min_time_gap'])

    def _scan_cron(self):
        """
        Get scan cron

        Returns:
            str

        """
        if cfg['portdetection.scan_type'] == ScanType.LIVE.value:
            return self.LIVE_SCAN_CRON

        return cfg['portdetection.periodic_scan.cron']
