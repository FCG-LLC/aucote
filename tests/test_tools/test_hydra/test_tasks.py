import ipaddress
import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from structs import Port, TransportProtocol, Node, Scan, ScanContext
from tools.hydra.parsers import HydraParser
from tools.hydra.tasks import HydraScriptTask
from utils import Config


class HydraScriptTaskTest(AsyncTestCase):
    OUTPUT_SUCCESSFUL = r'''Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-08-09 14:19:36
[DATA] max 1 task per 1 server, overall 64 tasks, 1 login try (l:1/p:1), ~0 tries per task
[DATA] attacking service ftp on port 21
[21][ftp] host: 192.168.56.102   login: msfadmin   password: msfadmin
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-08-09 14:19:37'''

    def setUp(self):
        super(HydraScriptTaskTest, self).setUp()
        self.aucote = MagicMock()
        self.port = Port(node=Node(ip='127.0.0.1', node_id=None), transport_protocol=TransportProtocol.TCP, number=22)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()
        self.exploit = Exploit(exploit_id=1)
        self.scan = Scan()
        self.context = ScanContext(aucote=self.aucote, scanner=None)

        self.hydra_script_task = HydraScriptTask(exploits=[self.exploit], context=self.context, port=self.port,
                                                 service=self.port.service_name, scan=self.scan,)
        self.hydra_script_task.store_scan_end = MagicMock()
        self.hydra_script_task.aucote.exploits.find.return_value = self.exploit

    def test_init(self):
        self.assertEqual(self.hydra_script_task.aucote, self.aucote)
        self.assertEqual(self.hydra_script_task._port, self.port)

    @patch('time.time', MagicMock(return_value=27.0))
    @patch('tools.common.command_task.cfg', new_callable=Config)
    @patch('tools.hydra.tasks.cfg', new_callable=Config)
    @gen_test
    async def test_storage(self, cfg, cfg_cct):
        cfg_cct._cfg = cfg._cfg = {
            'tools': {
                'hydra': {
                    'loginfile': None,
                    'passwordfile': None,
                    'timeout': 0
                }
            }
        }
        future = Future()
        future.set_result(MagicMock())
        self.hydra_script_task.command.async_call = MagicMock(return_value=future)
        self.hydra_script_task.aucote.kudu_queue = MagicMock()
        self.hydra_script_task.store_vulnerability = MagicMock()
        await self.hydra_script_task()

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