from unittest import TestCase
from xml.etree.ElementTree import Element

from tools.common.parsers import Parser, XMLParser
from utils.exceptions import NonXMLOutputException


class ParserTest(TestCase):
    OUTPUT = 'TEST_output'

    def setUp(self):
        self.parser = Parser()

    def test_parse(self):
        self.assertEqual(self.parser.parse(self.OUTPUT), self.OUTPUT)


class ParserXMLTest(TestCase):
    NON_XML = '''This is non XML output!'''
    SCRIPT_XML = '''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    def setUp(self):
        self.parser = XMLParser()

    def test_parse(self):
        self.assertIsInstance(self.parser.parse(self.SCRIPT_XML), Element)

    def test_parse_non_xml(self):
        self.assertRaises(NonXMLOutputException, self.parser.parse, self.NON_XML)
