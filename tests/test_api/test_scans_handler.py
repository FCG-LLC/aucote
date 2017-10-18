import json
from unittest.mock import MagicMock, patch

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.scans_handler import ScansHandler
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Node, Scan, TransportProtocol, Port, PortScan, NodeScan
from tests.test_api.test_api import APITest
from utils import Config


class ScansHandlerTest(APITest):
    def setUp(self):
        super(ScansHandlerTest, self).setUp()
        self.handler = ScansHandler(self.app, MagicMock(), aucote=self.aucote)

    def test_scans(self):
        expected = {
            "scans":
                [
                    {
                        'id': 2,
                        'url': self.get_url('/api/v1/scan/2'),
                        'protocol': 'UDP',
                        'start': 230,
                        'end': 447,
                        'scanner': 'udp',
                        'scanner_url': self.get_url('/api/v1/scanner/udp')
                    },
                    {
                        'id': 1,
                        'url': self.get_url('/api/v1/scan/1'),
                        'protocol': 'TCP',
                        'start': 123,
                        'end': 446,
                        'scanner': 'tcp',
                        'scanner_url': self.get_url('/api/v1/scanner/tcp')
                    }
            ]
        }
        response = self.fetch('/api/v1/scans', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertDictEqual(json.loads(response.body.decode()), expected)

    def test_scan(self):
        expected = {
            "scan": 1,
            "url": self.get_url('/api/v1/scan/1'),
            "nodes": [
                {
                    'id': 1,
                    'ip': '10.156.67.18',
                    "url": self.get_url('/api/v1/node/1'),
                    "node_id": 13,
                    "scan": 1,
                    "scan_url": self.get_url('/api/v1/scan/1')
                }
            ],
            "ports": ['10.156.67.18:34']
        }
        response = self.fetch('/api/v1/scan/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)