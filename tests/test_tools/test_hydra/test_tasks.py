import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from tools.hydra.parsers import HydraParser
from tools.hydra.tasks import HydraScriptTask


class HydraScriptTaskTest(TestCase):
    OUTPUT_SUCCESSFUL = r'''Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-08-09 14:19:36
[DATA] max 1 task per 1 server, overall 64 tasks, 1 login try (l:1/p:1), ~0 tries per task
[DATA] attacking service ftp on port 21
[21][ftp] host: 192.168.56.102   login: msfadmin   password: msfadmin
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-08-09 14:19:37'''

    def setUp(self):
        self.executor = MagicMock()
        self.port = MagicMock()
        self.port.number = 22
        self.port.node = MagicMock()
        self.port.node.ip = '127.0.0.1'
        self.port.service_name = 'ssh'

        self.hydra_script_task = HydraScriptTask(executor=self.executor, port=self.port, service=self.port.service_name)
        self.hydra_script_task.store_scan_end = MagicMock()
        self.exploit = Exploit(exploit_id=1)
        self.hydra_script_task.executor.exploits.find.return_value = self.exploit
        self.hydra_script_task.exploit = self.exploit

    def test_init(self):
        self.assertEqual(self.hydra_script_task.executor, self.executor)
        self.assertEqual(self.hydra_script_task._port, self.port)

    @patch('database.serializer.Serializer.serialize_port_vuln', MagicMock(return_value=None))
    def test_call(self):
        self.hydra_script_task.command.call = MagicMock(return_value=HydraParser.parse(self.OUTPUT_SUCCESSFUL))
        result = self.hydra_script_task()

        self.assertEqual(result[0].host, '192.168.56.102')
        self.assertEqual(result[0].login, 'msfadmin')
        self.assertEqual(result[0].password, 'msfadmin')

    def test_call_wihout_output(self):
        self.hydra_script_task.command.call = MagicMock(return_value=None)

        result = self.hydra_script_task()
        expected = None

        self.assertEqual(result, expected)

    def test_call_exception(self):
        self.hydra_script_task.command.call = MagicMock(side_effect=subprocess.CalledProcessError(MagicMock(), MagicMock()))

        result = self.hydra_script_task()
        expected = None

        self.assertEqual(result, expected)
        result = self.hydra_script_task.executor.storage.save_scan.call_args[1]

        self.assertEqual(result['port'].scan.start, 0)
        self.assertEqual(result['port'].scan.end, 0)
        self.assertEqual(result['exploit'], self.exploit)

    @patch('time.time', MagicMock(return_value=27.0))
    def test_storage(self):
        self.hydra_script_task.command.call = MagicMock(return_value=MagicMock())
        self.hydra_script_task.executor.kudu_queue = MagicMock()
        self.hydra_script_task.store_vulnerability = MagicMock()
        self.hydra_script_task()

        result = self.hydra_script_task.store_scan_end.call_args[1]
        expected = {
            'exploits': [self.exploit],
            'port': self.port,
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(self.port.scan.end, 27)
