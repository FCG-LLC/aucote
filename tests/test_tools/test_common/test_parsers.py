from unittest import TestCase
from xml.etree import ElementTree

from tools.common.parsers import Parser, XMLParser
from utils.exceptions import NonXMLOutputException


class ParserTest(TestCase):
    OUTPUT = 'TEST_output'

    def test_parse(self):
        self.assertEqual(Parser.parse(self.OUTPUT), self.OUTPUT)

class ParserXMLTest(TestCase):
    NON_XML = '''This is non XML output!'''
    SCRIPT_XML = '''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    def test_parse(self):
        self.assertIsInstance(XMLParser.parse(self.SCRIPT_XML), ElementTree.Element)

    def test_parse_non_xml(self):
        self.assertRaises(NonXMLOutputException, XMLParser.parse, self.NON_XML)
