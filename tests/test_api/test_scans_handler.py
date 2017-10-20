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
                        'end_human': '1970-01-01T00:07:27+00:00',
                        'start_human': '1970-01-01T00:03:50+00:00',
                        'scanner': 'udp',
                        'scanner_url': self.get_url('/api/v1/scanner/udp')
                    },
                    {
                        'id': 1,
                        'url': self.get_url('/api/v1/scan/1'),
                        'protocol': 'TCP',
                        'end_human': '1970-01-01T00:07:26+00:00',
                        'start_human': '1970-01-01T00:02:03+00:00',
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
        result = json.loads(response.body.decode())
        del result['navigation']
        del result['meta']
        self.assertEqual(result, expected)

    def test_scan(self):
        expected = {
            "scan": 1,
            "url": self.get_url('/api/v1/scan/1'),
            "end": 446,
            "start": 123,
            "nodes_scans": [
                {
                    'id': 1,
                    'ip': '10.156.67.18',
                    "url": self.get_url('/api/v1/node/1'),
                    "node_id": 13,
                    "scan": 1,
                    "scan_url": self.get_url('/api/v1/scan/1')
                }
            ],
            "ports_scans":
                [
                    {
                        'id': 2,
                        'port': {
                            'node_id': 75,
                            'node_ip': '10.156.67.34',
                            'port_number': 78,
                            'protocol': 'TCP'
                        },
                        'scan': 1,
                        'timestamp': 2345,
                        'timestamp_human': '1970-01-01T00:39:05+00:00',
                        'url': self.get_url('/api/v1/port/2')
                    },
                    {
                        'id': 1,
                        'port': {
                            'node_id': 13,
                            'node_ip': '10.156.67.18',
                            'port_number': 34,
                            'protocol': 'UDP',
                        },
                        'scan': 1,
                        'timestamp': 1234,
                        'timestamp_human': '1970-01-01T00:20:34+00:00',
                        'url': self.get_url('/api/v1/port/1')
                    }
                ]
        }
        response = self.fetch('/api/v1/scan/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['meta']
        self.assertEqual(result, expected)
