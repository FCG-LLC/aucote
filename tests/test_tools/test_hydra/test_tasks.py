import ipaddress
import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from structs import Port, TransportProtocol, Node, Scan
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
        self.aucote = MagicMock()
        self.port = Port(node=Node(ip='127.0.0.1', node_id=None), transport_protocol=TransportProtocol.TCP, number=22)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()
        self.exploit = Exploit(exploit_id=1)

        self.hydra_script_task = HydraScriptTask(exploits=[self.exploit], aucote=self.aucote, port=self.port,
                                                 service=self.port.service_name)
        self.hydra_script_task.store_scan_end = MagicMock()
        self.hydra_script_task.aucote.exploits.find.return_value = self.exploit

    def test_init(self):
        self.assertEqual(self.hydra_script_task.aucote, self.aucote)
        self.assertEqual(self.hydra_script_task._port, self.port)

    @patch('time.time', MagicMock(return_value=27.0))
    def test_storage(self):
        self.hydra_script_task.command.call = MagicMock(return_value=MagicMock())
        self.hydra_script_task.aucote.kudu_queue = MagicMock()
        self.hydra_script_task.store_vulnerability = MagicMock()
        self.hydra_script_task()

        result = self.hydra_script_task.store_scan_end.call_args[1]
        expected = {
            'exploits': [self.exploit],
            'port': self.port,
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(self.port.scan.end, 27)

    @patch('tools.hydra.tasks.cfg.get', MagicMock(side_effect=('test_logins', 'test_passwords')))
    def test_prepare_args_ipv6(self):
        node = Node(12, ipaddress.ip_address("::1"))
        self.port.node = node

        result = self.hydra_script_task.prepare_args()
        expected = ['-L', 'test_logins', '-6', '-P', 'test_passwords', '-s', '22', '::1', 'ssh']

        self.assertEqual(result, expected)