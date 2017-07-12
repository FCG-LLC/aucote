"""
This module contains class responsible scanning tasks.

"""
import ipaddress
from tornado.httpclient import HTTPError
import logging as log
import time
import ujson as json

from croniter import croniter
from netaddr import IPSet
from tornado.locks import Event

from aucote_cfg import cfg
from structs import Node, Scan, ScanType, TopisOSDiscoveryType, Service, CPEType, TransportProtocol
from utils.http_client import HTTPClient
from utils.time import parse_period, parse_time_to_timestamp


class ScanAsyncTask(object):
    """
    Parent class for all scanning tasks

    """
    LIVE_SCAN_CRON = '* * * * *'
    PROTOCOL = None

    def __init__(self, aucote):
        self._current_scan = []
        self.aucote = aucote
        self.scan_start = None
        self._shutdown_condition = Event()

    @property
    def shutdown_condition(self):
        """
        Event which is set when no scan in progress

        Returns:
            Event

        """
        return self._shutdown_condition

    @classmethod
    async def _get_topdis_nodes(cls):
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

                    try:
                        node.os.cpe = Service.build_cpe(product=node.os.name, version=node.os.version, part=CPEType.OS)
                    except:
                        node.os.cpe = None

                nodes.append(node)

        log.debug('Got %i nodes from topdis', len(nodes))
        return nodes

    async def _get_nodes_for_scanning(self, timestamp=None, protocol=None, filter_out_storage=True):
        """
        Get nodes for scan since timestamp.
            - If timestamp is None, it is equal: current timestamp - node scan period
            - Restrict nodes to allowed networks

        Args:
            timestamp (float):

        Returns:
            list

        """
        nodes = await self._get_topdis_nodes()

        if filter_out_storage:
            storage_nodes = self.storage.get_nodes(self._scan_interval(), protocol=protocol, timestamp=timestamp)
            nodes = list(set(nodes) - set(storage_nodes))

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
