from unittest import TestCase
from unittest.mock import MagicMock, call

from tools.whatweb.parsers import WhatWebParser
from tools.whatweb.structs import WhatWebPlugin, WhatWebTarget, WhatWebResult


class WhatWebParserTest(TestCase):
    JSON_MULTIPLE_LINES = """[
{"target":"http://jenkins.cs.int","http_status":301,"plugins":{"IP":{"string":["10.12.1.110"]},"Title":{"string":["301 Moved Permanently"]},"nginx":{"version":["1.4.6"]},"HTTPServer":{"os":["Ubuntu Linux"],"string":["nginx/1.4.6 (Ubuntu)"]},"Country":{"string":["RESERVED"],"module":["ZZ"]},"RedirectLocation":{"string":["https://jenkins.cs.int/"]}}},
{"target":"https://jenkins.cs.int/","http_status":403,"plugins":{"HttpOnly":{"string":["JSESSIONID.6d81b00c"]},"Jenkins":{"version":["2.62"]},"IP":{"string":["10.12.1.110"]},"nginx":{},"HTTPServer":{"string":["nginx"]},"Meta-Refresh-Redirect":{"string":["/login?from=%2F"]},"UncommonHeaders":{"string":["x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-hudson-cli-port,x-jenkins-cli-port,x-jenkins-cli2-port,x-you-are-authenticated-as,x-you-are-in-group-disabled,x-required-permission,x-permission-implied-by"]},"Script":{},"Country":{"string":["RESERVED"],"module":["ZZ"]},"Cookies":{"string":["JSESSIONID.6d81b00c"]}}},
{"target":"https://jenkins.cs.int/login?from=%2F","http_status":200,"plugins":{"HttpOnly":{"string":["JSESSIONID.6d81b00c"]},"Jenkins":{"version":["2.62"]},"IP":{"string":["10.12.1.110"]},"Title":{"string":["Jenkins"]},"nginx":{},"HTTPServer":{"string":["nginx"]},"UncommonHeaders":{"string":["x-content-type-options,x-hudson-theme,x-hudson,x-jenkins,x-jenkins-session,x-hudson-cli-port,x-jenkins-cli-port,x-jenkins-cli2-port,x-instance-identity"]},"Script":{"string":["text/javascript"]},"X-Frame-Options":{"string":["sameorigin"]},"Country":{"string":["RESERVED"],"module":["ZZ"]},"JQuery":{},"Cookies":{"string":["JSESSIONID.6d81b00c"]},"HTML5":{},"Prototype":{},"PasswordField":{"string":["j_password"]}}},
{}
]"""

    JSON_OUTPUT = """{"target":"http://jenkins.cs.int","http_status":301,"plugins":{"IP":{"string":["10.12.1.110"]},"Title":{"string":["301 Moved Permanently"]},"nginx":{"version":["1.4.6"]},"HTTPServer":{"os":["Ubuntu Linux"],"string":["nginx/1.4.6 (Ubuntu)"]},"Country":{"string":["RESERVED"],"module":["ZZ"]},"RedirectLocation":{"string":["https://jenkins.cs.int/"]}}}"""
    JSON_PLUGIN_OUTPUT = """"IP":{"string":["10.12.1.110"]}"""

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
        expected.outputs = ['output 1', 'test output', 'some other output']

        self.assertEqual(result.name, expected.name)
        self.assertCountEqual(result.outputs, expected.outputs)

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

    def test_parse(self):
        self.parser._parse_line = MagicMock()
        self.parser._parse_line.side_effect = (True, None, True)

        result = self.parser.parse(self.MULTIPLE_LINES_OUTPUT, '')

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
