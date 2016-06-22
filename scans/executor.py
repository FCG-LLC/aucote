from aucote_cfg import cfg
import urllib.request as http
from utils.threads import ThreadPool
from tools.nmap import *
import ipaddress
import logging as log
import json
from .structs import Node
from .tasks import PortScanTask

class Executor:
    '''
    Gets the information about nodes and starts the tasks
    '''

    _thread_pool = None

    _PORT_TO_TASK = {
        443: [SslHeartbleed, SslDhParams, SslPoodle, SslCcsInjection],
        8443: [SslHeartbleed, SslDhParams, SslPoodle, SslCcsInjection]
    }

    def __init__(self, db, scan_id):
        self._db = db
        self._scan_id = scan_id

    def run(self):
        nodes = self._get_nodes()
        ps = PortsScan()
        ports = ps.scan_ports(nodes)
        for port in ports:
            port.db_id = self._db.insert_port(port, self._scan_id)
        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))
        
        for port in ports:
            for cls in self._PORT_TO_TASK.get(port.number, tuple()):
                self.add_task(PortScanTask(cls, port))

        self._thread_pool.start()
        self._thread_pool.join()
        self._thread_pool.stop()

    def add_task(self, task):
        log.debug('Added task: %s', task)
        task.db = self._db
        task.executor = self
        task.scan_id = self._scan_id
        self._thread_pool.add_task(task)

    def _get_nodes(self):
        url = 'http://%s:%s/api/v1/nodes?ip=t'%(cfg.get('topdis.api.host'), cfg.get('topdis.api.port'))
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

