from unittest import TestCase

from tools.hydra.parsers import HydraParser


class HydraParserTest(TestCase):
    OUTPUT = """Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-08-09 15:38:17
[DATA] max 1 task per 1 server, overall 64 tasks, 1 login try (l:1/p:1), ~0 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.56.102   login: test_login   password: test_password
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-08-09 15:38:17"""

    FAIL_OUTPUT = """Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-08-09 15:46:32
[ERROR] Unknown service: udp://192.168.56.102:27"""
    OUTPUT_LINE = r"[80][http-get] host: 192.168.56.102   login: test_login   password: test_password"
    OUTPUT_LINE_WITH_SPACE_PASSWORD = r"[80][http-get] host: 192.168.56.102   login: test_login   password: test_password "
    OUTPUT_LINE_WITH_SPACE_LOGIN = r"[80][http-get] host: 192.168.56.102   login: test_login    password: test_password"
    OUTPUT_ERROR_LINE = r"[ERROR] could not connect to ssh://192.168.56.102:29 - Connection refused"
    OUTPUT_DATA_LINE = r"[DATA] attacking service ssh on port 29"


    def setUp(self):
        pass

    def test_init(self):
        hydra_results = HydraParser.parse(output=self.OUTPUT)
        self.assertEqual(hydra_results.success, 1)
        self.assertEqual(hydra_results.fail, 0)
        self.assertEqual(len(hydra_results), 1)

        self.assertEqual(hydra_results[0].login, 'test_login')
        self.assertEqual(hydra_results[0].password, 'test_password')
        self.assertEqual(hydra_results[0].port, 22)
        self.assertEqual(hydra_results[0].service, 'ssh')
        self.assertEqual(hydra_results[0].host, '192.168.56.102')

    def test_space_password(self):
        self.hydra_result = HydraParser.from_output(self.OUTPUT_LINE_WITH_SPACE_PASSWORD)
        self.assertEqual(self.hydra_result.port, 80)
        self.assertEqual(self.hydra_result.service, 'http-get')
        self.assertEqual(self.hydra_result.host, '192.168.56.102')
        self.assertEqual(self.hydra_result.login, 'test_login')
        self.assertEqual(self.hydra_result.password, 'test_password ')

    def test_space_login(self):
        self.hydra_result = HydraParser.from_output(output=self.OUTPUT_LINE_WITH_SPACE_LOGIN)
        self.assertEqual(self.hydra_result.port, 80)
        self.assertEqual(self.hydra_result.service, 'http-get')
        self.assertEqual(self.hydra_result.host, '192.168.56.102')
        self.assertEqual(self.hydra_result.login, 'test_login ')
        self.assertEqual(self.hydra_result.password, 'test_password')

    def test_output_error_line(self):
        self.assertEqual(HydraParser.from_output(self.OUTPUT_ERROR_LINE), None)

    def test_output_data_line(self):
        self.assertEqual(HydraParser.from_output(self.OUTPUT_DATA_LINE), None)
