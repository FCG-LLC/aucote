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

    def test_parse(self):
        result = HydraParser.parse(output=self.OUTPUT)
        self.assertEqual(result.success, 1)
        self.assertEqual(result.fail, 0)
        self.assertEqual(len(result), 1)

        self.assertEqual(result[0].login, 'test_login')
        self.assertEqual(result[0].password, 'test_password')
        self.assertEqual(result[0].port, 22)
        self.assertEqual(result[0].service, 'ssh')
        self.assertEqual(result[0].host, '192.168.56.102')

    def test_parse_output_with_space_password(self):
        result = HydraParser.from_output(self.OUTPUT_LINE_WITH_SPACE_PASSWORD)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.service, 'http-get')
        self.assertEqual(result.host, '192.168.56.102')
        self.assertEqual(result.login, 'test_login')
        self.assertEqual(result.password, 'test_password ')

    def test_parse_output_space_login(self):
        result = HydraParser.from_output(output=self.OUTPUT_LINE_WITH_SPACE_LOGIN)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.service, 'http-get')
        self.assertEqual(result.host, '192.168.56.102')
        self.assertEqual(result.login, 'test_login ')
        self.assertEqual(result.password, 'test_password')

    def test_output_error_line(self):
        result = HydraParser.from_output(self.OUTPUT_ERROR_LINE)
        expected = None

        self.assertEqual(result, expected)

    def test_output_data_line(self):
        result = HydraParser.from_output(self.OUTPUT_DATA_LINE)
        expected = None

        self.assertEqual(result, expected)
