from unittest import TestCase

from tools.what_web.structs import WhatWebPluginOutput, WhatWebResult, WhatWebResults


class WhatWebPluginOutputTest(TestCase):
    def setUp(self):
        self.output = WhatWebPluginOutput()
        self.output.name = 'test_name'
        self.output.outputs = ('test_output_1', 'test_output_2')

    def test_str(self):
        result = str(self.output)
        expected = ' - test_name: test_output_1, test_output_2'

        self.assertEqual(result, expected)


class WhatWebResultTest(TestCase):
    def setUp(self):
        self.result = WhatWebResult()
        self.result.address = 'test_address'
        self.result.plugins = ('test_plugin_1', 'test_plugin_2')
        self.result.status_code = 200
        self.result.status = 'OK'

    def test_str(self):
        result = str(self.result)
        expected = "test_address 200:\ntest_plugin_1\ntest_plugin_2"
        self.assertEqual(result, expected)

class WhatWebResultsTest(TestCase):
    def setUp(self):
        self.results = WhatWebResults()
        self.results.results = ('output_1', 'output_2')

    def test_str(self):
        result = str(self.results)
        expected = 'output_1\n----------\noutput_2'
        self.assertEqual(result, expected)
