import ipaddress
import json
from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.main_handler import MainHandler
from fixtures.exploits import Exploit
from scans.executor import Executor
from scans.scanner import Scanner
from structs import Port, Node, TransportProtocol
from tools.base import Tool
from tools.common.port_task import PortTask
from utils import Config


class UserAPITest(AsyncHTTPTestCase):
    def setUp(self):
        super(UserAPITest, self).setUp()
        self.aucote = MagicMock()
        self.handler = MainHandler(self.app, MagicMock(), aucote=self.aucote)
        self.scanner = Scanner(aucote=self.aucote)
        self.scanner.NAME = 'test_name'
        self.scanner.PROTOCOL = TransportProtocol.ALL

    def get_app(self):
        self.aucote = MagicMock()
        self.app = Application([('/', MainHandler, {'aucote': self.aucote})])
        return self.app

    @patch('api.main_handler.MainHandler.aucote_status')
    def test_user_profile_anonymous(self, mock_aucote_status):
        expected = {"test": "test_value"}
        mock_aucote_status.return_value = expected
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    @patch('api.main_handler.MainHandler.metadata')
    @patch('api.main_handler.MainHandler._scanners_status')
    def test_aucote_status(self, mock_scan_info, metadata):
        metadata.return_value = 'test_meta'
        self.aucote.task_manager.unfinished_tasks = 13

        result = self.handler.aucote_status()
        expected = {'scanners': mock_scan_info.return_value,
                    'meta': 'test_meta',
                    'unfinished_tasks': 13}

        self.assertEqual(result, expected)

    @patch('api.main_handler.time.time', MagicMock(return_value=16.7))
    def test_metadata(self):
        result = MainHandler.metadata()
        expected = {
            'timestamp': 16.7
        }

        self.assertEqual(result, expected)

    def test_format_nodes(self):
        node_1 = Node(node_id=13, ip=ipaddress.ip_address('127.0.0.5'))
        node_2 = Node(node_id=45, ip=ipaddress.ip_address('45.0.0.5'))

        expected = ['127.0.0.5[13]', '45.0.0.5[45]']
        result = self.handler._format_nodes([node_1, node_2])

        self.assertCountEqual(result, expected)

    @patch('api.main_handler.cfg', new_callable=Config)
    @patch('scans.scan_task.cfg', new_callable=Config)
    @patch('scans.scan_task.time.time', MagicMock(return_value=147))
    def test_scanner_status(self, cfg, cfg_scan_task):
        cfg['portdetection.test_name.scan_type'] = 'LIVE'
        cfg['portdetection.test_name.live_scan.min_time_gap'] = '45s'
        cfg['portdetection.test_name.ports.include'] = ['23']
        cfg['portdetection.test_name.ports.exclude'] = ['89']
        cfg['portdetection.test_name.networks.include'] = ['127.0.0.1/24']
        cfg['portdetection.test_name.networks.exclude'] = ['127.0.0.1/8']
        cfg_scan_task._cfg = cfg._cfg
        self.scanner.scan_start = 67.
        self.aucote.task_manager.cron_tasks = [self.scanner]
        self.scanner._current_scan = [Node(node_id=34, ip=ipaddress.ip_address('127.0.0.1'))]

        result = self.handler._scanners_status()
        expected = {
            'test_name': {
                'current_scan': ['127.0.0.1[34]'],
                'next_scan': 180.,
                'previous_scan': 60.,
                'protocol': 'ALL',
                'scan_start': 67.,
                'scan_type': 'LIVE',
                'ports': {
                    'included': ['23'],
                    'excluded': ['89']
                },
                'networks': {
                    'included': ['127.0.0.1/24'],
                    'excluded': ['127.0.0.1/8']
                },
                'cron': '* * * * *',
                'min_time_gap': 45.
            }
        }

        self.assertEqual(result, expected)
