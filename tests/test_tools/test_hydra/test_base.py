from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.hydra.base import HydraBase

@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class HydraBasetest(TestCase):
    OUTPUT_SUCCESSFUL = b'''Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-08-09 14:19:36
[DATA] max 1 task per 1 server, overall 64 tasks, 1 login try (l:1/p:1), ~0 tries per task
[DATA] attacking service ftp on port 21
[21][ftp] host: 192.168.56.102   login: msfadmin   password: msfadmin
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-08-09 14:19:37'''

    OUTPUT_UNSUCCESSFUL = b'''Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-08-09 14:20:17
[DATA] max 1 task per 1 server, overall 64 tasks, 1 login try (l:1/p:1), ~0 tries per task
[DATA] attacking service ftp on port 21
1 of 1 target completed, 0 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-08-09 14:20:21'''

    def setUp(self):
        self.executor = MagicMock()
        self.hydra = HydraBase(executor=self.executor)

    def test_init(self):
        self.assertEqual(self.hydra.executor, self.executor)

    @patch('subprocess.check_output', MagicMock(return_value=OUTPUT_SUCCESSFUL))
    def test_success(self):
        self.hydra_result = self.hydra.call()

        self.assertEqual(self.hydra_result.success, 1)
        self.assertEqual(self.hydra_result.all, 1)
        self.assertEqual(self.hydra_result[0].service, 'ftp')
        self.assertEqual(self.hydra_result[0].port.number, 21)
        self.assertEqual(self.hydra_result[0].host, '192.168.56.102')
        self.assertEqual(self.hydra_result[0].login, 'msfadmin')
        self.assertEqual(self.hydra_result[0].password, 'msfadmin')
