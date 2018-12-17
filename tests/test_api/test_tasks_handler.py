import json
from unittest.mock import MagicMock, patch

import ipaddress
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.tasks_handler import TasksHandler
from structs import Node, Port, TransportProtocol, ScanContext, TaskManagerType
from tools.common.port_task import PortTask
from utils.async_task_manager import AsyncTaskManager


class TasksHandlerTest(AsyncHTTPTestCase):
    def setUp(self):
        super(TasksHandlerTest, self).setUp()

    def get_app(self):
        self.aucote = MagicMock(unfinished_tasks=4)
        self.context = ScanContext(aucote=self.aucote, scanner=None)
        self.tasks = AsyncTaskManager()
        self.tasks._is_running = False
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
            self.tasks.add_task(PortTask(context=self.context,
                                         port=Port(
                                             node=Node(node_id=task['id'], ip=ipaddress.ip_address(task['ip'])),
                                             number=task['port'],
                                             transport_protocol=TransportProtocol.TCP,),
                                         exploits=[]))

        self.tasks._task_workers = {number: PortTask(context=self.context,
                                                     port=Port(
                                                         node=Node(node_id=task['id'],
                                                                   ip=ipaddress.ip_address(task['ip'])),
                                                         number=task['port'],
                                                         transport_protocol=TransportProtocol.TCP,),
                                                     exploits=[]) for number, task in enumerate(worker_tasks)}

        class test_function:
            def __str__(self):
                return 'test_function'

            def __call__(self, *args, **kwargs):
                pass

        self.tasks.add_crontab_task(test_function(), '0 0 0 0 0')
        self.tasks._task_workers.update({2: None, 3: None, 4: None})

        self.aucote.async_task_managers = {
            TaskManagerType.SCANNER: self.tasks
        }
        self.app = Application([
            (r"/api/v1/tasks", TasksHandler, {'aucote': self.aucote})])
        return self.app

    def test_tasks(self):
        expected = {
            'unfinished_tasks': 4,
            'scanner': {
                'unfinished_tasks': 3,
                'queue': [
                    '[+] [None] PortTask [on 127.0.0.1:45]',
                    '[+] [None] PortTask [on 127.0.0.2:56]',
                    '[+] [None] PortTask [on 127.0.0.3:67]'
                ],
                'workers': {
                    'count': 5,
                    'jobs': {
                        '0': '[+] [None] PortTask [on 127.0.0.4:78]',
                        '1': '[+] [None] PortTask [on 127.0.0.5:89]',
                        '2': None,
                        '3': None,
                        '4': None
                    }
                },
                'cron_tasks': [
                    {
                        'name': 'test_function',
                        'cron': '0 0 0 0 0',
                        'is_running': False
                    }
                ]
            }
        }
        response = self.fetch('/api/v1/tasks', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)
