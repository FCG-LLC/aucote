from unittest import TestCase

from tools.common.parsers import Parser


class ParserTest(TestCase):
    OUTPUT = 'TEST_output'

    def test_parse(self):
        self.assertEqual(Parser.parse(self.OUTPUT), self.OUTPUT)