import json
from unittest.mock import MagicMock, patch

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.scanners_handler import ScannersHandler
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Node
from utils import Config


class ScannersHandlerTest(AsyncHTTPTestCase):
    def setUp(self):
        super(ScannersHandlerTest, self).setUp()
        self.handler = ScannersHandler(self.app, MagicMock(), aucote=self.aucote)

    def get_app(self):
        self.aucote = MagicMock()
        self.scanner = TCPScanner(aucote=self.aucote)
        self.scanner.NAME = 'test_name'
        self.scanner.scan_start = 1290
        self.scanner.nodes = [Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))]
        self.aucote.scanners = [self.scanner, ToolsScanner(name='tools', aucote=self.aucote)]
        self.app = Application([
            (r"/api/v1/scanner/([\w_]+)", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/scanners", ScannersHandler, {'aucote': self.aucote})])
        return self.app

    def test_scanners(self):
        expected = {
            "scanners":
                [
                    {
                        'name': 'test_name',
                        'url': self.get_url('/api/v1/scanners/test_name')
                    },
                    {
                        'name': 'tools',
                        'url': self.get_url('/api/v1/scanners/tools')
                    }
            ]
        }
        response = self.fetch('/api/v1/scanners', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.time.time', MagicMock(return_value=1356))
    def test_scanner(self, cfg):
        cfg['portdetection.test_name.scan_type'] = 'PERIODIC'
        cfg['portdetection.test_name.periodic_scan.cron'] = '* * * * *'
        expected = {
            'current_scan': 1290,
            'current_scan_human': '1970-01-01T00:21:30+00:00',
            'next_scan': 1380,
            'next_scan_human': '1970-01-01T00:23:00+00:00',
            'nodes': ['127.0.0.1[1]'],
            'previous_scan': 1260,
            'previous_scan_human': '1970-01-01T00:21:00+00:00',
            'scan': 'test_name',
            'scanners': {'IPv4': ['masscan'], 'IPv6': ['nmap']},
            'status': 'IDLE'
        }
        response = self.fetch('/api/v1/scanner/test_name', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    def test_tool_scanner(self):
        expected = {'code': 'Security scanners are not implemented right now'}
        response = self.fetch('/api/v1/scanner/tools', method='GET')
        self.assertEqual(response.code, 500)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    def test_non_existing_scanner(self):
        expected = {'code': 'Scanner not found'}
        response = self.fetch('/api/v1/scanner/none_exist', method='GET')
        self.assertEqual(response.code, 404)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)