import ipaddress
import logging as log
from tornado.httpclient import HTTPError
import ujson
import time
import netifaces
from croniter import croniter
from netaddr import IPSet
from tornado.locks import Event

from aucote_cfg import cfg
from structs import Node, Scan, TopisOSDiscoveryType, Service, CPEType, ScanType, PhysicalPort
from tools.nmap.tool import NmapTool
from utils.http_client import HTTPClient
from utils.time import parse_time_to_timestamp, parse_period


class ScanTask(object):
    LIVE_SCAN_CRON = '* * * * *'
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    NAME = None

    def __init__(self, aucote, scan_only=True):
        self.aucote = aucote
        self._shutdown_condition = Event()
        self.start = None
        self._scan_only = scan_only

    async def __call__(self):
        raise NotImplementedError

    async def _get_nodes_for_scanning(self, timestamp=None):
        """
        Get nodes for scan since timestamp.
            - If timestamp is None, it is equal: current timestamp - node scan period
            - Restrict nodes to allowed networks

        Args:
            timestamp (float|None):

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

    async def _get_topdis_nodes(self):
        """
        Get nodes from todis application

        """
        url = 'http://%s:%s/api/v1/nodes?ip=t' % (cfg['topdis.api.host'], cfg['topdis.api.port'])
        try:
            resource = await HTTPClient.instance().get(url)
        except HTTPError:
            log.exception('Cannot connect to topdis: %s:%s', cfg['topdis.api.host'], cfg['topdis.api.port'])
            return []
        except ConnectionError:
            log.exception('Cannot connect to topdis: %s:%s', cfg['topdis.api.host'], cfg['topdis.api.port'])
            return []

        nodes_cfg = ujson.loads(resource.body)

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

    def _get_networks_list(self):
        """
        Returns list of networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg['portdetection.{0}.networks.include'.format(self.NAME)])
        except KeyError:
            log.error("Please set portdetection.{0}.networks.include in configuration file!".format(self.NAME))
            exit()

    def _get_excluded_networks_list(self):
        """
        List of excluded networks from configuration file

        Returns:
            IPSet: set of networks

        """
        try:
            return IPSet(cfg['portdetection.{0}.networks.exclude'.format(self.NAME)])
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

    def _scan_interval(self):
        """
        Get interval between particular node scan

        Returns:
            int

        """
        if cfg['portdetection.{0}.scan_type'.format(self.NAME)] == ScanType.PERIODIC.value:
            return 0

        return parse_period(cfg['portdetection.{0}.live_scan.min_time_gap'.format(self.NAME)])

    def _scan_cron(self):
        """
        Get scan cron

        Returns:
            str

        """
        if cfg['portdetection.{0}.scan_type'.format(self.NAME)] == ScanType.LIVE.value:
            return self.LIVE_SCAN_CRON

        return cfg['portdetection.{0}.periodic_scan.cron'.format(self.NAME)]

    @property
    def previous_scan(self):
        """
        Returns previous scan timestamp

        Returns:
            float

        """

        return croniter(self._scan_cron(), time.time()).get_prev()

    @property
    def next_scan(self):
        """
        Time of next regular scan

        Returns:
            float

        """
        return croniter(self._scan_cron(), time.time()).get_next()

    def get_ports_for_scan(self, nodes):
        """
        Get ports for scanning. Topdis node data combined with stored open ports data.

        Returns:
            list

        """
        return self.storage.get_ports_by_nodes(nodes=nodes, timestamp=self.previous_scan)

    def _get_special_ports(self):
        return_value = []
        if cfg['service.scans.physical']:
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addr = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addr:
                    continue

                port = PhysicalPort()
                port.interface = interface
                port.scan = Scan(start=time.time())
                return_value.append(port)

        return return_value

    def _filter_out_ports(self, ports):
        port_range_allow = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.include'],
                                                    udp=cfg['portdetection.udp.ports.include'])

        port_range_deny = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.exclude'],
                                                   udp=cfg['portdetection.udp.ports.exclude'])

        return [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]
