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
        self.executor = MagicMock(storage=Storage(":memory:"))
        self.command = Command(executor=self.executor)
        self.command.COMMON_ARGS = []

    def test_init(self):
        self.assertEqual(self.command.executor, self.executor)

    @patch('subprocess.check_output', MagicMock(return_value=SCRIPT_XML))
    def test_stdout(self):
        result = self.command.call()
        self.assertEqual(result, self.SCRIPT_XML.decode("utf-8"))

    @patch('subprocess.check_output', MagicMock(side_effect=subprocess.CalledProcessError(returncode=1, cmd='masscan')))
    def test_stderr(self):
        self.assertRaises(subprocess.CalledProcessError, self.command.call)

    @patch('tools.common.command.Storage')
    @patch('tools.common.command.time.time')
    def test_store_scan_end_info(self, mock_time, mock_storage):
        port = MagicMock()

        self.command.executor.exploits = range(5)
        self.command.store_scan_end_info(port)

        result = mock_storage.return_value.__enter__.return_value.save_scan.call_args_list

        self.assertEqual(len(result), 5)

        for exploit in self.command.executor.exploits:
            self.assertEqual(result[exploit][1]['exploit'], exploit)
            self.assertEqual(result[exploit][1]['port'], port)
            self.assertEqual(result[exploit][1]['finish_scan'], mock_time.return_value)


@patch('aucote_cfg.cfg.get', MagicMock(return_value='test'))
class CommandXMLTest(TestCase):
    SCRIPT_XML = b'''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    NON_XML = b'''This is non XML output!'''

    def setUp(self):
        self.executor = MagicMock()
        self.command_xml = CommandXML(self.executor)
        self.command_xml.COMMON_ARGS = []

    def test_init(self):
        self.assertEqual(self.command_xml.executor, self.executor)

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