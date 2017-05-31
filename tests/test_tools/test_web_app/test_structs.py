from unittest import TestCase

from tools.whatweb.structs import WhatWebPlugin, WhatWebTarget, WhatWebResult


class WhatWebPluginOutputTest(TestCase):
    def setUp(self):
        self.output = WhatWebPlugin()
        self.output.name = 'test_name'
        self.output.outputs = ('test_output_1', 'test_output_2')

    def test_str(self):
        result = str(self.output)
        expected = ' - test_name: test_output_1, test_output_2'

        self.assertEqual(result, expected)


class WhatWebResultTest(TestCase):
    def setUp(self):
        self.result = WhatWebTarget()
        self.result.uri = 'test_address'
        self.result.plugins = ('test_plugin_1', 'test_plugin_2')
        self.result.status = 200

    def test_str(self):
        result = str(self.result)
        expected = "test_address 200:\ntest_plugin_1\ntest_plugin_2"
        self.assertEqual(result, expected)

class WhatWebResultsTest(TestCase):
    def setUp(self):
        self.results = WhatWebResult()
        self.results.targets = ('output_1', 'output_2')

    def test_str(self):
        result = str(self.results)
        expected = 'output_1\n----------\noutput_2'
        self.assertEqual(result, expected)
