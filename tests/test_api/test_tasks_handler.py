import json
from unittest.mock import MagicMock, patch

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.main_handler import MainHandler
from api.scanners_handler import ScannersHandler
from api.tasks_handler import TasksHandler
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from structs import Node, Port, TransportProtocol
from tools.common.port_task import PortTask
from utils import Config
from utils.async_task_manager import AsyncTaskManager
from utils.task import Task


class TasksHandlerTest(AsyncHTTPTestCase):
    def setUp(self):
        super(TasksHandlerTest, self).setUp()
        self.handler = MainHandler(self.app, MagicMock(), aucote=self.aucote)

    def get_app(self):
        self.aucote = MagicMock(unfinished_tasks=4)
        self.tasks = AsyncTaskManager()
        tasks = [
            {'port': 45, 'id': 1, 'ip': '127.0.0.1'},
            {'port': 56, 'id': 2, 'ip': '127.0.0.2'},
            {'port': 67, 'id': 3, 'ip': '127.0.0.3'},
        ]
        worker_tasks = [
            {'port': 78, 'id': 4, 'ip': '127.0.0.4'},
            {'port': 89, 'id': 5, 'ip': '127.0.0.5'},
        ]
        for task in tasks:
            self.tasks.add_task(PortTask(aucote=self.aucote,
                                         scan=None,
                                         port=Port(
                                             node=Node(node_id=task['id'], ip=ipaddress.ip_address(task['ip'])),
                                             number=task['port'],
                                             transport_protocol=TransportProtocol.TCP,),
                                         exploits=[]))

        self.tasks._task_workers = [PortTask(aucote=self.aucote,
                                             scan=None,
                                             port=Port(
                                                 node=Node(node_id=task['id'], ip=ipaddress.ip_address(task['ip'])),
                                                 number=task['port'],
                                                 transport_protocol=TransportProtocol.TCP,),
                                             exploits=[]) for task in worker_tasks]
        self.tasks._task_workers.extend([None, None, None])

        self.aucote.async_task_manager = self.tasks
        self.app = Application([
            (r"/api/v1/tasks", TasksHandler, {'aucote': self.aucote})])
        return self.app

    def test_tasks(self):
        expected = {
            'unfinished_tasks': 4,
            'queue': [
                'PortTask on 127.0.0.1:45',
                'PortTask on 127.0.0.2:56',
                'PortTask on 127.0.0.3:67'
            ],
            'workers': {
                'count': 5,
                'jobs': [
                    'PortTask on 127.0.0.4:78',
                    'PortTask on 127.0.0.5:89'
                ]
            }
        }
        response = self.fetch('/api/v1/tasks', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)