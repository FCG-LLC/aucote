from aucote_cfg import cfg
import urllib.request as http
from utils.threads import ThreadPool
from tools.nmap import PortsScan
import ipaddress
import logging as log
import json
from structs import Node, Scan
from .tasks import NmapPortScanTask
from .nmap_scripts_cfg import SERVICE_TO_SCRIPTS, PORT_TO_SCRIPTS
import datetime

class Executor:
    '''
    Gets the information about nodes and starts the tasks
    '''

    _thread_pool = None
    _exploits = None

    def __init__(self, kudu_queue):
        self._kudu_queue = kudu_queue

    def run(self):
        scan = Scan()
        scan.start = datetime.datetime.utcnow()
        nodes = self._get_nodes()
        ps = PortsScan()
        ports = ps.scan_ports(nodes)
        if self._exploits is None:
            from fixtures.exploits import read_exploits
            self._exploits = read_exploits()
        for port in ports:
            port.scan = scan
            #port.db_id = self._db.insert_port(port, self._scan_id)
        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))
        
        for port in ports:
            all_scripts = set()
            all_scripts.update(SERVICE_TO_SCRIPTS.get(port.service_name, tuple()))
            all_scripts.update(PORT_TO_SCRIPTS.get(port.number, tuple()))
            self.add_task(NmapPortScanTask(port, all_scripts))

        self._thread_pool.start()
        self._thread_pool.join()
        self._thread_pool.stop()
        end = datetime.datetime.utcnow()

    def add_task(self, task):
        log.debug('Added task: %s', task)
        task.kudu_queue = self._kudu_queue
        task.executor = self
        task.exploits = self._exploits
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

