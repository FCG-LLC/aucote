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


class Executor:
    """
    Gets the information about nodes and starts the tasks
    """

    _thread_pool = None
    _exploits = None

    def __init__(self, kudu_queue):
        self._kudu_queue = kudu_queue

    def run(self):
        """
        Start tasks: scanning nodes and ports
        """
        scan = Scan()
        scan.start = datetime.datetime.utcnow()
        nodes = self._get_nodes()
        scanner = MasscanPorts()
        ports = scanner.scan_ports(nodes)

        if self._exploits is None:
            from fixtures.exploits import read_exploits
            self._exploits = read_exploits()

        for port in ports:
            port.scan = scan

        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))

        for port in ports:
            self.add_task(NmapPortInfoTask(port))

        self._thread_pool.start()
        self._thread_pool.join()
        self._thread_pool.stop()

    def add_task(self, task):
        """
        Add task for executing
        """
        log.debug('Added task: %s', task)
        task.kudu_queue = self._kudu_queue
        task.executor = self
        task.exploits = self._exploits
        self._thread_pool.add_task(task)

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
