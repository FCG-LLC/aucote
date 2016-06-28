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

class Executor:
    '''
    Gets the information about nodes and starts the tasks
    '''

    _thread_pool = None
    _exploits = None

    def __init__(self, db):
        self._db = db

    def run(self):
        scan = Scan()
        scan.start = datetime.datetime.utcnow()
        scan.db_id = self._db.insert_scan(scan.start)
        nodes = self._get_nodes()
        ps = PortsScan()
        ports = ps.scan_ports(nodes)
        if self._exploits is None:
            self._exploits = self._db.get_exploits()
        for port in ports:
            port.scan = scan
            port.db_id = self._db.insert_port(port, self._scan_id)
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
        self._db.update_scan(scan_id, end)

    def add_task(self, task):
        log.debug('Added task: %s', task)
        task.db = self._db
        task.executor = self
        task.scan_id = self._scan_id
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

