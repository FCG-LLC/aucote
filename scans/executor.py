"""
This is main module of aucote scanning functionality.

"""

import ipaddress
import logging as log
import json
import time
from urllib.error import URLError
import urllib.request as http

from aucote_cfg import cfg
from tools.nmap.tasks.port_info import NmapPortInfoTask
from tools.masscan import MasscanPorts
from utils.exceptions import TopdisConnectionException
from utils.storage import Storage
from utils.time import parse_period
from structs import Node, Scan


class Executor(object):
    """
    Gets the information about nodes and starts the tasks

    """

    def __init__(self, aucote, nodes=None):
        """
        Init executor. Sets kudu_queue and nodes

        """

        self.aucote = aucote
        self.nodes = nodes or self._get_nodes()
        self.storage.save_nodes(self.nodes)

    @property
    def storage(self):
        """
        Returns aucote's storage

        Returns:
            Storage

        """
        return self.aucote.storage

    @property
    def kudu_queue(self):
        """
        Returns aucote's kudu queue

        Returns:
            KuduQueue

        """
        return self.aucote.kudu_queue

    @property
    def thread_pool(self):
        """
        Returns aucote's thread pool

        Returns:
            ThreadPool

        """
        return self.aucote.thread_pool

    def run(self):
        """
        Start tasks: scanning nodes and ports

        """
        scan = Scan()
        scan.start = time.time()
        scanner = MasscanPorts(executor=self.aucote)
        ports = scanner.scan_ports(self.nodes)
        storage_ports = self.storage.get_ports(parse_period(cfg.get('service.scans.port_period')))

        ports = self._get_ports_for_scanning(ports, storage_ports)
        log.info("Found %i recently not scanned ports", len(ports))

        with Storage(filename=self.storage.filename) as storage:
            storage.save_ports(ports)

        for port in ports:
            port.scan = scan

        for port in ports:
            self.add_task(NmapPortInfoTask(executor=self.aucote, port=port))

    def __call__(self, *args, **kwargs):
        """
        Making executor callable for working as task

        Args:
            *args:
            **kwargs:

        Returns:

        """
        return self.run()

    def add_task(self, task):
        """
        Add task to aucote pool

        Args:
            task (Task):

        Returns:
            None

        """
        return self.aucote.add_task(task)

    @property
    def exploits(self):
        """
        Returns:
            exploits

        """
        return self.aucote.exploits

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
        topdis_nodes = self._get_nodes()
        storage_nodes = self.storage.get_nodes()

        for node in storage_nodes:
            try:
                topdis_nodes.remove(node)
            except ValueError:
                continue

        return topdis_nodes

    @classmethod
    def _get_ports_for_scanning(cls, ports, storage_ports):
        """
        Diff ports for scanning

        Args:
            ports (list):
            storage_ports (list):

        Returns:
            list

        """

        ports = ports[:]

        for port in storage_ports:
            try:
                ports.remove(port)
            except ValueError:
                continue

        return ports
