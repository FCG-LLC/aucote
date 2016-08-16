"""
This is main module of aucote scanning functionality.
"""

import urllib.request as http
import ipaddress
import logging as log
import json
import datetime
from aucote_cfg import cfg
from utils.threads import ThreadPool
from tools.masscan import MasscanPorts
from structs import Node, Scan
from .tasks import NmapPortInfoTask


class Executor(object):
    """
    Gets the information about nodes and starts the tasks
    """

    _thread_pool = None
    _slow_thread_pool = None
    _exploits = None

    def __init__(self, kudu_queue):
        self._kudu_queue = kudu_queue
        self.nodes = self._get_nodes()

    def run(self):
        """
        Start tasks: scanning nodes and ports
        """
        scan = Scan()
        scan.start = datetime.datetime.utcnow()
        scanner = MasscanPorts(executor=self)
        ports = scanner.scan_ports(self.nodes)

        if self._exploits is None:
            from fixtures.exploits import read_exploits
            self._exploits = read_exploits()

        for port in ports:
            port.scan = scan

        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))
        self._slow_thread_pool = ThreadPool(1)

        for port in ports:
            self.add_task(NmapPortInfoTask(executor=self, port=port))

        self._thread_pool.start()
        self._thread_pool.join()
        self._thread_pool.stop()

        self._slow_thread_pool.start()
        self._slow_thread_pool.join()
        self._slow_thread_pool.stop()

    def add_task(self, task):
        """
        Add task for executing
        """
        log.debug('Added task: %s', task)
        self._thread_pool.add_task(task)

    def add_slow_task(self, task):
        """
        Add task for executing
        """
        log.debug('Added task: %s', task)
        self._slow_thread_pool.add_task(task)

    @property
    def exploits(self):
        """
        Returns: exploits
        """
        return self._exploits

    @property
    def kudu_queue(self):
        """
        Returns: kudu_queue
        """
        return self._kudu_queue

    @classmethod
    def _get_nodes(cls):
        """
        Get nodes from todis application
        """
        url = 'http://%s:%s/api/v1/nodes?ip=t' % (cfg.get('topdis.api.host'), cfg.get('topdis.api.port'))
        resource = http.urlopen(url)
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
