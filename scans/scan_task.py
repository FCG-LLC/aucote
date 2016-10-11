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

from aucote_cfg import cfg
from scans.executor import Executor
from structs import Node
from tools.masscan import MasscanPorts
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
        scanner = MasscanPorts()
        nodes = self._get_nodes_for_scanning()

        log.info('Scanning %i nodes', len(nodes))

        if not nodes:
            return

        ports = scanner.scan_ports(nodes)
        self.storage.save_nodes(nodes)

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
