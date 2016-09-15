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
from scans.task_mapper import TaskMapper
from tools.nmap.tasks.port_info import NmapPortInfoTask
from tools.masscan import MasscanPorts
from utils.exceptions import TopdisConnectionException
from utils.threads import ThreadPool
from structs import Node, Scan


class Executor(object):
    """
    Gets the information about nodes and starts the tasks

    """

    _thread_pool = None

    def __init__(self, kudu_queue, exploits, storage):
        """
        Init executor. Sets kudu_queue and nodes

        """
        self._kudu_queue = kudu_queue
        self.storage = storage

        self.nodes = self._get_nodes()

        self.task_mapper = TaskMapper(self)
        self._exploits = exploits

    def run(self):
        """
        Start tasks: scanning nodes and ports

        """
        scan = Scan()
        scan.start = time.time()
        scanner = MasscanPorts(executor=self)
        ports = scanner.scan_ports(self.nodes)

        for port in ports:
            port.scan = scan

        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))

        for port in ports:
            self.add_task(NmapPortInfoTask(executor=self, port=port))

        self._thread_pool.start()
        self._thread_pool.join()
        self._thread_pool.stop()

    def add_task(self, task):
        """
        Add task for executing
        """
        log.debug('Added task: %s', task)
        self._thread_pool.add_task(task)

    @property
    def exploits(self):
        """
        Returns:
            exploits

        """
        return self._exploits

    @property
    def kudu_queue(self):
        """
        Returns:
            kudu_queue

        """
        return self._kudu_queue

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
                node = Node()
                node.ip = ipaddress.ip_address(node_ip)
                node.name = node_struct['displayName']
                node.id = node_struct['id']
                nodes.append(node)
        return nodes

    def _get_nodes_for_scanning(self):
        """
        Returns:
            list of nodes to be scan

        """
        topdis_nodes = self._get_nodes()
        storage_nodes = self.storage.get_nodes()

        to_remove = set()

        for node in topdis_nodes:
            for st_node in storage_nodes:
                if node.id == st_node.id and str(node.ip) == str(st_node.ip):
                    to_remove.add(node)

        for node in to_remove:
            topdis_nodes.remove(node)

        return topdis_nodes
