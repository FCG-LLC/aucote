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

    @patch('api.main_handler.MainHandler.thread_pool_status')
    @patch('api.main_handler.MainHandler.storage_status')
    @patch('api.main_handler.MainHandler.scanning_status')
    def test_aucote_status(self, mock_scan_info, storage_status, thread_pool_status):
        thread_pool_status.return_value = {'test': 'test_2'}
        storage_status.return_value = 'test_storage'

        result = self.handler.aucote_status()
        expected = {'test': 'test_2', 'scanner': mock_scan_info.return_value, 'storage': 'test_storage'}

        self.assertEqual(result, expected)

    @patch('api.main_handler.cfg', new_callable=Config)
    @patch('api.main_handler.MainHandler.scheduler_task_status')
    def test_scanning_info(self, task_status, mock_cfg):
        mock_cfg._cfg = {
            'service': {
                'scans': {
                    'networks': ['test_cfg1'],
                    'ports': ['test_cfg2'],
                }
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
            'scheduler': ['test', 'test'],
            'networks': ['test_cfg1'],
            'ports': ['test_cfg2'],
            'previous_scan': scan_thread.previous_scan
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

    def test_storage_task_info(self):
        storage = MagicMock()
        storage.filename = 'test_filename'
        result = MainHandler.storage_status(storage)

        expected = {
            'path': 'test_filename'
        }

        self.assertDictEqual(result, expected)

    @patch('api.main_handler.MainHandler.thread_pool_thread_status')
    @patch('api.main_handler.MainHandler.task_status')
    def test_stats(self, mock_status, thread_pool_thread_status):
        thread_pool = MagicMock()

        thread1 = MagicMock()
        thread2 = MagicMock()
        thread3 = MagicMock(task=None)
        thread4 = MagicMock()

        thread_pool.threads = [thread1, thread2, thread3]
        thread_pool.task_queue = [thread4]
        thread_pool.num_threads = 123

        expected = {
            'queue': [
                mock_status.return_value
            ],
            'threads': [
                thread_pool_thread_status.return_value,
                thread_pool_thread_status.return_value
            ],
            'queue_length': 1,
            'threads_length': 2,
            'threads_limit': 123
        }

        result = self.handler.thread_pool_status(thread_pool)

        self.assertDictEqual(result, expected)

    @patch('utils.threads.time.time', MagicMock(return_value=300))
    def test_thread_status(self):
        thread = MagicMock()
        thread.start_time = 100

        result = MainHandler.thread_pool_thread_status(thread)
        expected = MainHandler.task_status(thread.task)
        expected['start_time'] = 100
        expected['duration'] = 200

        self.assertEqual(result, expected)

    def test_get_task_info(self):
        task = MagicMock()

        result = MainHandler.task_status(task)
        expected = {
            'type': 'MagicMock',
            'data': task.get_info.return_value
        }

        self.assertDictEqual(result, expected)