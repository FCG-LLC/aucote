import json
from unittest.mock import MagicMock

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from api.nodes_handler import NodesHandler
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Node, Scan, TransportProtocol, Port, PortScan, NodeScan


class NodesHandlerTest(AsyncHTTPTestCase):
    def setUp(self):
        super(NodesHandlerTest, self).setUp()
        self.handler = NodesHandler(self.app, MagicMock(), aucote=self.aucote)

    def get_app(self):
        self.aucote = MagicMock()
        self.scan_1 = Scan(start=123, end=446, protocol=TransportProtocol.TCP, scanner='tcp', rowid=3)
        self.scan_2 = Scan(start=230, end=447, protocol=TransportProtocol.UDP, scanner='udp', rowid=5)

        node_1 = Node(node_id=13, ip=ipaddress.ip_address("10.156.67.18"))
        node_2 = Node(node_id=75, ip=ipaddress.ip_address("10.156.67.34"))
        self.nodes = [
            NodeScan(node=node_1, scan=self.scan_1, rowid=13, timestamp=45),
            NodeScan(node=node_2, scan=self.scan_2, rowid=91, timestamp=88)
        ]

        self.port_1 = Port(node=node_1, number=34, transport_protocol=TransportProtocol.UDP)
        self.port_2 = Port(node=node_2, number=78, transport_protocol=TransportProtocol.TCP)
        self.port_scan_1 = PortScan(port=self.port_1, timestamp=1234, scan=self.scan_1, rowid=13)
        self.port_scan_2 = PortScan(port=self.port_2, timestamp=2345, scan=self.scan_1, rowid=15)
        self.aucote.storage.get_ports_scans_by_scan.return_value = [self.port_scan_1, self.port_scan_2]

        self.scanner = TCPScanner(aucote=self.aucote)
        self.scanner.NAME = 'test_name'
        self.scanner.scan_start = 1290
        self.scanner.nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.aucote.scanners = [self.scanner, ToolsScanner(name='tools', aucote=self.aucote)]
        self.app = Application([
            (r"/api/v1/node/([\w_]+)", NodesHandler, {'aucote': self.aucote}),
            (r"/api/v1/nodes", NodesHandler, {'aucote': self.aucote})])
        return self.app

    def test_nodes_scans(self):
        self.aucote.storage.nodes_scans.return_value = self.nodes
        expected = {
            'nodes':
                [
                    {
                        'id': 13,
                        'ip': '10.156.67.18',
                        'node_id': 13,
                        'scan': 3,
                        'scan_url': self.get_url('/api/v1/scan/3'),
                        'url': self.get_url('/api/v1/node/13')
                    },
                    {
                        'id': 91,
                        'ip': '10.156.67.34',
                        'node_id': 75,
                        'scan': 5,
                        'scan_url': self.get_url('/api/v1/scan/5'),
                        'url': self.get_url('/api/v1/node/91')
                    }
                ]
        }

        response = self.fetch('/api/v1/nodes', method='GET')
        
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    def test_node_details(self):
        self.aucote.storage.node_scan_by_id.return_value = self.nodes[0]
        self.aucote.storage.scans_by_node_scan.return_value = [self.scan_1, self.scan_2]

        expected = {
            'id': 13,
            'ip': '10.156.67.18',
            'node_id': 13,
            'scan': 3,
            'scan_url': self.get_url('/api/v1/scan/3'),
            'scans': [
                {
                    'end': 446,
                    'id': 3,
                    'protocol': 'TCP',
                    'scanner': 'tcp',
                    'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                    'start': 123,
                    'url': self.get_url('/api/v1/scan/3')
                },
                {
                    'end': 447,
                    'id': 5,
                    'protocol': 'UDP',
                    'scanner': 'udp',
                    'scanner_url': self.get_url('/api/v1/scanner/udp'),
                    'start': 230,
                    'url': self.get_url('/api/v1/scan/5')
                }
            ],
            'url': self.get_url('/api/v1/node/13')
        }

        response = self.fetch('/api/v1/node/3', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)
