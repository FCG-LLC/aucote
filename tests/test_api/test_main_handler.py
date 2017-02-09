import ipaddress
import json
from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.main_handler import MainHandler
from fixtures.exploits import Exploit
from scans.executor import Executor
from structs import Port, Node
from tools.base import Tool
from tools.common.port_task import PortTask
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
    @patch('api.main_handler.MainHandler.thread_pool_status')
    @patch('api.main_handler.MainHandler.storage_status')
    @patch('api.main_handler.MainHandler.scanning_status')
    def test_aucote_status(self, mock_scan_info, storage_status, thread_pool_status, metadata):
        thread_pool_status.return_value = {'test': 'test_2'}
        storage_status.return_value = 'test_storage'
        metadata.return_value = 'test_meta'

        result = self.handler.aucote_status()
        expected = {'test': 'test_2', 'scanner': mock_scan_info.return_value, 'storage': 'test_storage',
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
                thread_pool_thread_status.return_value,
                thread_pool_thread_status.return_value
            ],
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

        self.assertEqual(result, expected)

    def test_thread_status_task_is_none(self):
        thread = MagicMock()
        thread.task = None

        result = MainHandler.thread_pool_thread_status(thread)
        expected = {}

        self.assertEqual(result, expected)

    @patch('api.main_handler.MainHandler.detailed_task_status')
    def test_get_task_info(self, mock_status):
        task = MagicMock()

        result = MainHandler.task_status(task)
        expected = {
            'type': 'MagicMock',
            'data': mock_status.return_value
        }

        self.assertDictEqual(result, expected)

    def test_detailed_task_status_tool(self):
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=12)
        port = Port(node=node, number=20, transport_protocol=None)

        task = Tool(config=None, executor=None, exploits=None, port=port)

        result = MainHandler.detailed_task_status(task)
        expected = {
            'port': str(port)
        }

        self.assertDictEqual(result, expected)

    @patch('api.main_handler.time.time', MagicMock(side_effect=(100, 120, 170)))
    def test_detailed_task_status_port_task(self):
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=12)
        port = Port(node=node, number=20, transport_protocol=None)
        exploits = [
            Exploit(exploit_id=1, name='test_1'),
            Exploit(exploit_id=1, name='test_2'),
            Exploit(exploit_id=1, name='test_3'),
            Exploit(exploit_id=1, name='test_4'),
            Exploit(exploit_id=1, name='test_5'),
        ]

        task = PortTask(executor=None, exploits=exploits, port=port)

        result = MainHandler.detailed_task_status(task)
        expected = {
            'port': str(port),
            'exploits': ['test_1', 'test_2', 'test_3', 'test_4', 'test_5', ],
            'creation_time': 120
        }

        self.assertDictEqual(result, expected)

    @patch('scans.executor.cfg', new_callable=Config)
    def test_detailed_task_status_executor(self, cfg):
        cfg._cfg = {
            'service': {
                'scans': {
                    'broadcast': False
                }
            }
        }
        node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=12)
        ports = [
            Port(node=node, number=20, transport_protocol=None),
            Port(node=node, number=22, transport_protocol=None),
            Port(node=node, number=24, transport_protocol=None)]
        task = Executor(aucote=MagicMock(), nodes=ports)

        result = MainHandler.detailed_task_status(task)
        expected = {
            'nodes': ['127.0.0.1:20', '127.0.0.1:22', '127.0.0.1:24']
        }

        self.assertDictEqual(result, expected)
