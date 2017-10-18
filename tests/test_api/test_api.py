from unittest.mock import MagicMock

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from api.kill_handler import KillHandler
from api.main_handler import MainHandler
from api.nodes_handler import NodesHandler
from api.ports_handler import PortsHandler
from api.scanners_handler import ScannersHandler
from api.scans_handler import ScansHandler
from api.tasks_handler import TasksHandler
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Scan, TransportProtocol, Node, NodeScan, Port, PortScan
from utils.storage import Storage


class APITest(AsyncHTTPTestCase):
    def setUp(self, *args, **kwargs):
        self.maxDiff = None
        super(APITest, self).setUp(*args, **kwargs)

    def get_app(self):
        self.aucote = MagicMock()
        self.storage = Storage(filename=":memory:")
        self.aucote.storage = self.storage

        self.storage.connect()
        self.storage.init_schema()
        self.scan_1 = Scan(start=123, end=446, protocol=TransportProtocol.TCP, scanner='tcp')
        self.scan_2 = Scan(start=230, end=447, protocol=TransportProtocol.UDP, scanner='udp')

        self.storage.save_scan(self.scan_1)
        self.storage.save_scan(self.scan_2)

        self.node_1 = Node(node_id=13, ip=ipaddress.ip_address("10.156.67.18"))
        self.node_2 = Node(node_id=75, ip=ipaddress.ip_address("10.156.67.34"))
        self.node_scan_1 = NodeScan(node=self.node_1, scan=self.scan_1, timestamp=45)
        self.node_scan_2 = NodeScan(node=self.node_2, scan=self.scan_2, timestamp=88)
        self.node_scan_3 = NodeScan(node=self.node_1, scan=self.scan_2, timestamp=67)

        self.storage.save_node_scan(self.node_scan_1)
        self.storage.save_node_scan(self.node_scan_2)
        self.storage.save_node_scan(self.node_scan_3)

        self.port_1 = Port(node=self.node_1, number=34, transport_protocol=TransportProtocol.UDP)
        self.port_2 = Port(node=self.node_2, number=78, transport_protocol=TransportProtocol.TCP)
        self.port_scan_1 = PortScan(port=self.port_1, timestamp=1234, scan=self.scan_1, rowid=13)
        self.port_scan_2 = PortScan(port=self.port_2, timestamp=2345, scan=self.scan_1, rowid=15)

        self.storage.save_port_scan(self.port_scan_1)

        self.scanner = TCPScanner(aucote=self.aucote)
        self.scanner.NAME = 'test_name'
        self.scanner.scan_start = 1290
        self.scanner.nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.aucote.scanners = [self.scanner, ToolsScanner(name='tools', aucote=self.aucote)]
        self.app = Application([
            (r"/api/v1/status", MainHandler, {'aucote': self.aucote}),
            (r"/api/v1/kill", KillHandler, {'aucote': self.aucote}),
            (r"/api/v1/scanner/([\w_]+)", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/scanners", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/tasks", TasksHandler, {'aucote': self.aucote}),
            (r"/api/v1/scans", ScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/scan/([\d]+)", ScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/nodes", NodesHandler, {'aucote': self.aucote}),
            (r"/api/v1/node/([\d]+)", NodesHandler, {'aucote': self.aucote}),
            (r"/api/v1/ports", PortsHandler, {'aucote': self.aucote}),
            (r"/api/v1/port/([\d]+)", PortsHandler, {'aucote': self.aucote}),
        ])

        return self.app
