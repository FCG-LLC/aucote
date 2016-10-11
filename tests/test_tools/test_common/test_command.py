import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch
from xml.etree.ElementTree import Element

from tools.common import Command
from tools.common.command import CommandXML
from utils.exceptions import NonXMLOutputException
from utils.storage import Storage


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class CommandTest(TestCase):
    """
    Test system command with and without stderr.
    """

    SCRIPT_XML = b'''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    def setUp(self):
        self.command = Command()
        self.command.COMMON_ARGS = []

    @patch('subprocess.check_output', MagicMock(return_value=SCRIPT_XML))
    def test_stdout(self):
        result = self.command.call()
        self.assertEqual(result, self.SCRIPT_XML.decode("utf-8"))

    @patch('subprocess.check_output', MagicMock(side_effect=subprocess.CalledProcessError(returncode=1, cmd='masscan')))
    def test_stderr(self):
        self.assertRaises(subprocess.CalledProcessError, self.command.call)


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class CommandXMLTest(TestCase):
    SCRIPT_XML = b'''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    NON_XML = b'''This is non XML output!'''

    def setUp(self):
        self.command_xml = CommandXML()
        self.command_xml.COMMON_ARGS = []

    @patch('subprocess.check_output', MagicMock(return_value=SCRIPT_XML))
    def test_stdout(self):
        result = self.command_xml.call()

        self.assertIsInstance(result, Element)
        self.assertEqual(result.tag, 'script')

    @patch('subprocess.check_output', MagicMock(return_value=b''))
    def test_empty_output(self):
        self.assertRaises(NonXMLOutputException, self.command_xml.call)

    @patch('subprocess.check_output', MagicMock(return_value=NON_XML))
    def test_without_xml_output(self):
        self.assertRaises(NonXMLOutputException, self.command_xml.call)