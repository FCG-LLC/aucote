from unittest import TestCase
from unittest.mock import MagicMock, call

from tools.whatweb.parsers import WhatWebParser
from tools.whatweb.structs import WhatWebPluginOutput, WhatWebResult, WhatWebResults


class WhatWebParserTest(TestCase):
    MULTIPLE_LINES_OUTPUT = """http://jenkins.cs.int/a?a=we wqe [301 Moved Permanently] Country[RESERVED][ZZ]

https://jenkins.cs.int/a?a=we%20wqe [403 Forbidden] Cookies[JSESSIONID.6d81b00c]
https://jenkins.cs.int/login?from=%2Fa%3Fa%3Dwe%252520wqe [200 OK] Cookies[JSESSIONID.6d81b00c]"""

    ERROR_OUTPUT = """ERROR Redirection broken: http://jenkins.cs.int/a/ s/ - bad URI(is not URI?): http://jenkins.cs.int/a/ s/"""

    OUTPUT = """http://10.12.2.159:1032 [200 OK] JQuery, PasswordField[pma_p,assword]"""

    PLUGIN_OUTPUT = """plugin_name[output 1][test output][some other output]"""

    def setUp(self):
        self.parser = WhatWebParser()

    def test_plugin_output_parse(self):
        result = self.parser._parse_plugin_string(self.PLUGIN_OUTPUT)
        expected = WhatWebPluginOutput()
        expected.name = 'plugin_name'
        expected.outputs = ['output 1', 'test output', 'some other output']

        self.assertEqual(result.name, expected.name)
        self.assertCountEqual(result.outputs, expected.outputs)

    def test_plugin_output_parse_corrupt(self):
        result = self.parser._parse_plugin_string('')
        self.assertIsNone(result)

    def test_parse_line(self):
        self.parser._parse_plugin_string = MagicMock()

        result = self.parser._parse_line(self.OUTPUT)

        plugin_1 = WhatWebPluginOutput()
        plugin_1.name = 'JQuery'

        plugin_2 = WhatWebPluginOutput()
        plugin_2.name = 'PasswordField'
        plugin_2.outputs = ['pma_p,assword']

        self.assertEqual(result.status, 'OK')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.address, 'http://10.12.2.159:1032')
        self.assertEqual(len(result.plugins), 2)

        self.parser._parse_plugin_string.assert_has_calls((call('JQuery'), call('PasswordField[pma_p,assword]')))

    def test_parse_error_line(self):
        result = self.parser._parse_line(self.ERROR_OUTPUT)
        self.assertIsNone(result)

    def test_parse(self):
        self.parser._parse_line = MagicMock()
        self.parser._parse_line.side_effect = (True, None, True)

        result = self.parser.parse(self.MULTIPLE_LINES_OUTPUT, '')

        self.assertIsInstance(result, WhatWebResults)
        self.assertEqual(len(result.results), 2)
        self.parser._parse_line.assert_has_calls(
            (call('http://jenkins.cs.int/a?a=we wqe [301 Moved Permanently] Country[RESERVED][ZZ]'),
             call('https://jenkins.cs.int/a?a=we%20wqe [403 Forbidden] Cookies[JSESSIONID.6d81b00c]'),
             call('https://jenkins.cs.int/login?from=%2Fa%3Fa%3Dwe%252520wqe [200 OK] Cookies[JSESSIONID.6d81b00c]')))

    def test_get_plugin_name_parsing_error(self):
        self.parser.plugin_name_regex = MagicMock()
        self.parser.plugin_name_regex.match.return_value = None
        result = self.parser._get_plugin_name("test")

        self.assertIsNone(result)
