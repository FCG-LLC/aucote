from unittest.mock import MagicMock

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from api.kill_handler import KillHandler
from api.nodes_handler import NodesHandler
from api.ports_handler import PortsHandler
from api.scanners_handler import ScannersHandler
from api.scans_handler import ScansHandler
from api.security_scans_handler import SecurityScansHandler
from api.tasks_handler import TasksHandler
from api.vulnerabilitites_handler import VulnerabilitiesHandler
from fixtures.exploits import Exploit
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Scan, TransportProtocol, Node, NodeScan, Port, PortScan, SecurityScan, Vulnerability
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

        for scan in (self.scan_1, self.scan_2):
            self.storage.save_scan(scan)

        self.node_1 = Node(node_id=13, ip=ipaddress.ip_address("10.156.67.18"))
        self.node_2 = Node(node_id=75, ip=ipaddress.ip_address("10.156.67.34"))

        self.node_scan_1 = NodeScan(node=self.node_1, scan=self.scan_1, timestamp=45)
        self.node_scan_2 = NodeScan(node=self.node_2, scan=self.scan_2, timestamp=88)
        self.node_scan_3 = NodeScan(node=self.node_1, scan=self.scan_2, timestamp=67)

        for node_scan in (self.node_scan_1, self.node_scan_2, self.node_scan_3):
            self.storage.save_node_scan(node_scan)

        self.port_1 = Port(node=self.node_1, number=34, transport_protocol=TransportProtocol.UDP)
        self.port_2 = Port(node=self.node_2, number=78, transport_protocol=TransportProtocol.TCP)
        self.port_scan_1 = PortScan(port=self.port_1, timestamp=1234, scan=self.scan_1, rowid=13)
        self.port_scan_2 = PortScan(port=self.port_2, timestamp=2345, scan=self.scan_1, rowid=15)

        for port_scan in (self.port_scan_1, self.port_scan_2):
            self.storage.save_port_scan(port_scan)

        self.exploit_1 = Exploit(exploit_id=14, name='test_name', app='test_app')
        self.exploit_2 = Exploit(exploit_id=2, name='test_name_2', app='test_app_2')

        self.security_scan_1 = SecurityScan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_1, scan_start=178,
                                            scan_end=851)
        self.security_scan_2 = SecurityScan(exploit=self.exploit_2, port=self.port_1, scan=self.scan_1, scan_start=109,
                                            scan_end=775)
        self.security_scan_3 = SecurityScan(exploit=self.exploit_1, port=self.port_1, scan=self.scan_2, scan_start=114,
                                            scan_end=981)

        for scan in (self.security_scan_1, self.security_scan_2, self.security_scan_3):
            self.storage.save_sec_scan(scan)

        self.vulnerability_1 = Vulnerability(exploit=self.exploit_1, port=self.port_1, cvss="6.8", cve="CVE-2017-1231",
                                             scan=self.scan_1, output="Vulnerable stuff", vuln_time=134, subid=34)
        self.vulnerability_2 = Vulnerability(exploit=self.exploit_1, port=self.port_1, cvss="6.8", cve="CVE-2017-1231",
                                             scan=self.scan_2, output="Vulnerable stuff", vuln_time=718, subid=34)

        for vulnerability in (self.vulnerability_1, self.vulnerability_2):
            self.storage.save_vulnerability(vulnerability)

        self.scanner = TCPScanner(aucote=self.aucote)
        self.scanner.NAME = 'test_name'
        self.scanner.scan_start = 1290
        self.scanner.nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.aucote.scanners = [self.scanner, ToolsScanner(name='tools', aucote=self.aucote)]
        self.app = Application((url, handler, {'aucote': self.aucote}) for url, handler in [
            (r"/api/v1/kill", KillHandler),
            (r"/api/v1/scanners", ScannersHandler),
            (r"/api/v1/scanners/([\w_]+)", ScannersHandler),
            (r"/api/v1/tasks", TasksHandler),
            (r"/api/v1/scans", ScansHandler),
            (r"/api/v1/scans/([\d]+)", ScansHandler),
            (r"/api/v1/nodes", NodesHandler),
            (r"/api/v1/nodes/([\d]+)", NodesHandler),
            (r"/api/v1/ports", PortsHandler),
            (r"/api/v1/ports/([\d]+)", PortsHandler),
            (r"/api/v1/sec_scans", SecurityScansHandler),
            (r"/api/v1/sec_scans/([\d]+)", SecurityScansHandler),
            (r"/api/v1/vulnerabilities", VulnerabilitiesHandler),
            (r"/api/v1/vulnerabilities/([\d]+)", VulnerabilitiesHandler),
        ])

        return self.app
