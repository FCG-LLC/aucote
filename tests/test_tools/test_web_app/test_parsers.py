from unittest import TestCase
from unittest.mock import MagicMock, call

from tools.whatweb.parsers import WhatWebParser
from tools.whatweb.structs import WhatWebPlugin, WhatWebTarget, WhatWebResult


class WhatWebParserTest(TestCase):
    JSON_MULTIPLE_LINES = """[
{"target":"http://jenkins.cs.int","http_status":301,"plugins":{}},
{"target":"https://jenkins.cs.int/","http_status":403,"plugins":{}},
{"target":"https://jenkins.cs.int/login?from=%2F","http_status":200,"plugins":{}},
{}
]"""

    JSON_TARGET = {
        "target": "http://jenkins.cs.int",
        "http_status": 301,
        "plugins": {
            "IP": {
                "string": ["10.12.1.110"]
            },
            "HTTPServer": {
                "os": ["Ubuntu Linux"],
                "string": ["nginx/1.4.6 (Ubuntu)"]
            },
        }
    }

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
        expected = WhatWebPlugin()
        expected.name = 'plugin_name'
        expected.string = ['output 1', 'test output', 'some other output']

        self.assertEqual(result.name, expected.name)
        self.assertCountEqual(result.string, expected.string)

    def test_plugin_output_parse_corrupt(self):
        result = self.parser._parse_plugin_string('')
        self.assertIsNone(result)

    def test_parse_line(self):
        self.parser._parse_plugin_string = MagicMock()

        result = self.parser._parse_line(self.OUTPUT)

        plugin_1 = WhatWebPlugin()
        plugin_1.name = 'JQuery'

        plugin_2 = WhatWebPlugin()
        plugin_2.name = 'PasswordField'
        plugin_2.outputs = ['pma_p,assword']

        self.assertEqual(result.status, 200)
        self.assertEqual(result.uri, 'http://10.12.2.159:1032')
        self.assertEqual(len(result.plugins), 2)

        self.parser._parse_plugin_string.assert_has_calls((call('JQuery'), call('PasswordField[pma_p,assword]')))

    def test_parse_error_line(self):
        result = self.parser._parse_line(self.ERROR_OUTPUT)
        self.assertIsNone(result)

    def test_parse_text(self):
        self.parser._parse_line = MagicMock()
        self.parser._parse_line.side_effect = (True, None, True)

        result = self.parser.parse_text(self.MULTIPLE_LINES_OUTPUT, '')

        self.assertIsInstance(result, WhatWebResult)
        self.assertEqual(len(result.targets), 2)
        self.parser._parse_line.assert_has_calls(
            (call('http://jenkins.cs.int/a?a=we wqe [301 Moved Permanently] Country[RESERVED][ZZ]'),
             call('https://jenkins.cs.int/a?a=we%20wqe [403 Forbidden] Cookies[JSESSIONID.6d81b00c]'),
             call('https://jenkins.cs.int/login?from=%2Fa%3Fa%3Dwe%252520wqe [200 OK] Cookies[JSESSIONID.6d81b00c]')))

    def test_get_plugin_name_parsing_error(self):
        self.parser.plugin_name_regex = MagicMock()
        self.parser.plugin_name_regex.match.return_value = None
        result = self.parser._get_plugin_name("test")

        self.assertIsNone(result)

    def test_get_plugin_from_dict(self):
        name = 'test_name'
        plugin = {
            "string": ["301 Moved Permanently"],
            "os": "test_os",
            "account": "test_account",
            "model": "test_model",
            "firmware": "test_firmware",
            "module": "test_module",
            "filepath": "test_filepath"
        }

        result = self.parser._get_plugin_from_dict(name, plugin)
        self.assertEqual(result.name, name)
        self.assertEqual(result.os, 'test_os')
        self.assertEqual(result.account, 'test_account')
        self.assertEqual(result.model, 'test_model')
        self.assertEqual(result.firmware, 'test_firmware')
        self.assertEqual(result.module, 'test_module')
        self.assertEqual(result.filepath, 'test_filepath')
        self.assertEqual(result.string, ['301 Moved Permanently'])

    def test_get_plugin_from_dict_empty(self):
        name = 'test_name'
        plugin = {}

        result = self.parser._get_plugin_from_dict(name, plugin)
        self.assertEqual(result.name, name)
        self.assertIsNone(result.os)
        self.assertIsNone(result.account)
        self.assertIsNone(result.model)
        self.assertIsNone(result.firmware)
        self.assertIsNone(result.module)
        self.assertIsNone(result.filepath)
        self.assertEqual(result.string, [])

    def test_get_target_from_dict(self):
        self.parser._get_plugin_from_dict = MagicMock()
        result = self.parser._get_target_from_dict(self.JSON_TARGET)

        self.assertEqual(result.uri, "http://jenkins.cs.int")
        self.assertEqual(result.status, 301)
        self.assertEqual(len(result.plugins), 2)
        self.parser._get_plugin_from_dict.assert_has_calls((
            call("IP", {
                "string": ["10.12.1.110"]
            }),
            call("HTTPServer", {
                "os": ["Ubuntu Linux"],
                "string": ["nginx/1.4.6 (Ubuntu)"]
            })
        ), any_order=True)

    def test_parse_json(self):
        self.parser._get_target_from_dict = MagicMock()
        result = self.parser.parse_json(self.JSON_MULTIPLE_LINES, self.ERROR_OUTPUT)

        self.assertEqual(len(result.targets), 3)
        self.parser._get_target_from_dict.has_calls((
            call({"target": "http://jenkins.cs.int", "http_status": 301, "plugins": {}}),
            call({"target": "https://jenkins.cs.int/", "http_status": 403, "plugins": {}}),
            call({"target": "https://jenkins.cs.int/login?from=%2F", "http_status": 200, "plugins": {}}),
        ), any_order=True)

    def test_parse(self):
        self.parser.parse_json = MagicMock()
        stdout = "test_stdout"
        stderr = "test_stderr"
        result = self.parser.parse(stdout, stderr)
        self.parser.parse_json.assert_called_once_with(stdout, stderr)
        self.assertEqual(result, self.parser.parse_json.return_value)
