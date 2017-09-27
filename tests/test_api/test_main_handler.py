import json
from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.main_handler import MainHandler
from utils import Config


class UserAPITest(AsyncHTTPTestCase):
    def setUp(self):
        super(UserAPITest, self).setUp()
        self.handler = MainHandler(self.app, MagicMock(), aucote=self.aucote)

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
    @patch('api.main_handler.MainHandler.scanning_status')
    def test_aucote_status(self, mock_scan_info, metadata):
        metadata.return_value = 'test_meta'

        result = self.handler.aucote_status()
        expected = {'scanner': mock_scan_info.return_value,
                    'meta': 'test_meta'}

        self.assertEqual(result, expected)

    @patch('api.main_handler.time.time', MagicMock(return_value=16.7))
    def test_metadata(self):
        result = MainHandler.metadata()
        expected = {
            'timestamp': 16.7
        }

        self.assertEqual(result, expected)

    @patch('api.main_handler.cfg', new_callable=Config)
    @patch('api.main_handler.MainHandler.scheduler_task_status')
    def test_scanning_info(self, task_status, mock_cfg):
        mock_cfg._cfg = {
            'portdetection': {
                'networks': {
                    'include': ['test_cfg1.in'],
                    'exclude': ['test_cfg1.ex'],
                },
                'ports': {
                    'tcp': {
                        'include': ['test_cfg2.in'],
                        'exclude': ['test_cfg2.ex'],
                    },
                    'udp': {
                        'include': ['udp_1'],
                        'exclude': ['udp_2']
                    },
                    'sctp': {
                        'include': ['sctp_1'],
                        'exclude': ['sctp_2']
                    }
                },
                'scan_type': 'PERIODIC'
            }
        }
        scan_thread = MagicMock()
        scan_thread.current_scan = [
            MagicMock(ip='127.0.0.1'),
            MagicMock(ip='::1'),
        ]
        scan_thread.tasks = (1, 2)
        task_status.return_value = 'test'

        result = self.handler.scanning_status(scan_thread)
        expected = {
            'nodes': [
                '127.0.0.1',
                '::1'
            ],
            'networks': {
                'include': ['test_cfg1.in'],
                'exclude': ['test_cfg1.ex'],
            },
            'ports': {
                'tcp': {
                    'include': ['test_cfg2.in'],
                    'exclude': ['test_cfg2.ex'],
                },
                'udp': {
                    'include': ['udp_1'],
                    'exclude': ['udp_2']
                },
                'sctp': {
                    'include': ['sctp_1'],
                    'exclude': ['sctp_2']
                }
            },
            'previous_scan': scan_thread.previous_scan,
            'previous_tool_scan': scan_thread.previous_tool_scan,
            'next_scan': scan_thread.next_scan,
            'next_tool_scan': scan_thread.next_tool_scan,
            'scan_cron': scan_thread._scan_cron(),
            'scan_interval': scan_thread._scan_interval(),
            'scan_type': 'PERIODIC'
        }

        self.assertCountEqual(result, expected)

    def test_scheduler_task_status(self):
        task = MagicMock()
        task.action.__name__ = 'test_name'
        task.time = 17

        expected = {
            'action': 'test_name',
            'time': 17
        }
        result = MainHandler.scheduler_task_status(task)

        self.assertCountEqual(result, expected)
