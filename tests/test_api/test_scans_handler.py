import json
from unittest.mock import MagicMock, patch

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.scans_handler import ScansHandler
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Node, Scan, TransportProtocol, Port, PortScan, NodeScan
from utils import Config


class ScansHandlerTest(AsyncHTTPTestCase):
    def setUp(self):
        super(ScansHandlerTest, self).setUp()
        self.handler = ScansHandler(self.app, MagicMock(), aucote=self.aucote)

    def get_app(self):
        self.aucote = MagicMock()
        scan_1 = Scan(start=123, end=446, protocol=TransportProtocol.TCP, scanner='tcp', rowid=3)
        scan_2 = Scan(start=230, end=447, protocol=TransportProtocol.UDP, scanner='udp', rowid=5)
        self.aucote.storage.scans.return_value = [scan_1, scan_2]

        node_1 = Node(node_id=13, ip=ipaddress.ip_address("10.156.67.18"))
        node_2 = Node(node_id=75, ip=ipaddress.ip_address("10.156.67.34"))
        self.nodes = [
            NodeScan(node=node_1, scan=scan_1, rowid=13, timestamp=45),
            NodeScan(node=node_2, scan=scan_2, rowid=91, timestamp=88)
        ]
        self.aucote.storage.nodes_scans_by_scan.return_value = self.nodes

        self.port_1 = Port(node=node_1, number=34, transport_protocol=TransportProtocol.UDP)
        self.port_2 = Port(node=node_2, number=78, transport_protocol=TransportProtocol.TCP)
        self.port_scan_1 = PortScan(port=self.port_1, timestamp=1234, scan=scan_1, rowid=13)
        self.port_scan_2 = PortScan(port=self.port_2, timestamp=2345, scan=scan_1, rowid=15)
        self.aucote.storage.get_ports_scans_by_scan.return_value = [self.port_scan_1, self.port_scan_2]

        self.scanner = TCPScanner(aucote=self.aucote)
        self.scanner.NAME = 'test_name'
        self.scanner.scan_start = 1290
        self.scanner.nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.aucote.scanners = [self.scanner, ToolsScanner(name='tools', aucote=self.aucote)]
        self.app = Application([
            (r"/api/v1/scan/([\w_]+)", ScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/scans", ScansHandler, {'aucote': self.aucote})])
        return self.app

    def test_scans(self):
        expected = {
            "scans":
                [
                    {
                        'id': 3,
                        'url': self.get_url('/api/v1/scan/3'),
                        'protocol': 'TCP',
                        'start': 123,
                        'end': 446,
                        'scanner': 'tcp',
                        'scanner_url': self.get_url('/api/v1/scanner/tcp')
                    },
                    {
                        'id': 5,
                        'url': self.get_url('/api/v1/scan/5'),
                        'protocol': 'UDP',
                        'start': 230,
                        'end': 447,
                        'scanner': 'udp',
                        'scanner_url': self.get_url('/api/v1/scanner/udp')
                    },
            ]
        }
        response = self.fetch('/api/v1/scans', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertCountEqual(json.loads(response.body.decode()), expected)

    def test_scan(self):
        self.maxDiff = None
        expected = {
            "scan": 3,
            "url": self.get_url('/api/v1/scan/3'),
            "nodes": [
                {
                    'id': 13,
                    'ip': '10.156.67.18',
                    "url": self.get_url('/api/v1/node/13'),
                    "node_id": 13,
                    "scan": 3,
                    "scan_url": self.get_url('/api/v1/scan/3')
                },
                {
                    'id': 91,
                    'ip': '10.156.67.34',
                    'node_id': 75,
                    'scan': 5,
                    'scan_url': self.get_url('/api/v1/scan/5'),
                    'url': self.get_url('/api/v1/node/91')
                }
            ],
            "ports": ['10.156.67.18:34', '10.156.67.34:78']
        }
        response = self.fetch('/api/v1/scan/3', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)
