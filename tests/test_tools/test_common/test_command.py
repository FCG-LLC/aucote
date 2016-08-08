import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch
from xml.etree.ElementTree import Element

import aucote_cfg
from tools.common import Command
from utils.exceptions import NonXMLOutputException

@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class CommandTest(TestCase):
    '''
    Test system command with and without stderr.
    '''

    SCRIPT_XML = '''<?xml version="1.0"?>
        <script output="">
        </script>
        '''
    NON_XML = '''This is non xml output!'''

    def setUp(self):
        self.command = Command()
        self.command.COMMON_ARGS = []

    @patch('subprocess.check_output', MagicMock(return_value=SCRIPT_XML))
    def test_stdout(self):
        result = self.command.call()
        self.assertIsInstance(result, Element)
        self.assertEqual(result.tag, 'script')

    @patch('subprocess.check_output', MagicMock(side_effect=subprocess.CalledProcessError(returncode=1, cmd='test')))
    def test_stderr(self):
        self.assertRaises(SystemExit, self.command.call)

    @patch('subprocess.check_output', MagicMock(return_value=''))
    def test_empty_output(self):
        self.assertRaises(NonXMLOutputException, self.command.call)

    @patch('subprocess.check_output', MagicMock(return_value=NON_XML))
    def test_without_xml_output(self):
        self.assertRaises(NonXMLOutputException, self.command.call)
