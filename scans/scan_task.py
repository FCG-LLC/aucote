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
from utils.storage import Storage
from utils.task import Task
from utils.time import parse_period


class ScanTask(Task):
    """
    Class responsible for scanning

    """
    def __init__(self, nodes=None, *args, **kwargs):
        super(ScanTask, self).__init__(*args, **kwargs)
        self.nodes = nodes or self._get_nodes()
        self.scheduler = sched.scheduler(time.time)
        self.scan_period = parse_period(cfg.get('service.scans.period'))
        self.storage = None

    def run(self):
        """
        Periodically run scanning. Function run itself every period time.

        Returns:
            None
        """
        self.scheduler.enter(self.scan_period, 1, self.run)
        scanner = MasscanPorts(executor=self.executor)
        nodes = self._get_nodes_for_scanning()
        self.storage.save_nodes(nodes)
        ports = scanner.scan_ports(nodes)

        self.executor.add_task(Executor(aucote=self.executor, nodes=ports))

    def __call__(self, *args, **kwargs):
        with Storage(filename=self.executor.storage.filename) as storage:
            self.storage = storage
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
        storage_nodes = self.storage.get_nodes()

        for node in storage_nodes:
            try:
                topdis_nodes.remove(node)
            except ValueError:
                continue

        return topdis_nodes
