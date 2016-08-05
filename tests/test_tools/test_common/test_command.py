import subprocess
from unittest import TestCase
from unittest.mock import patch
from xml.etree.ElementTree import Element

from tools.common import Command


class Patch:
    '''
    Mock-up methods
    '''

    SCRIPT_XML = '''<?xml version="1.0"?>
        <script output="">
        </script>
        '''

    @staticmethod
    def cfg_get(*args, **kwargs):
        return 'test'

    @staticmethod
    def check_output(command, stderr):
        return Patch.SCRIPT_XML

    @staticmethod
    def check_output_error(command, stderr):
        stderr.write(b"This is example standard error output text!")
        raise subprocess.CalledProcessError(returncode=1, cmd='test')


class CommandTest(TestCase):
    '''
    Test system command with and without stderr.
    '''

    @patch('subprocess.check_output', Patch.check_output)
    @patch('aucote_cfg.cfg.get', Patch.cfg_get)
    def test_command_stdout(self):
        command = Command()
        command.COMMON_ARGS = []
        result = command.call()

        self.assertIsInstance(result, Element)
        self.assertEqual(result.tag, 'script')

    @patch('subprocess.check_output', Patch.check_output_error)
    @patch('aucote_cfg.cfg.get', Patch.cfg_get)
    def test_command_stderr(self):
        command = Command()
        command.COMMON_ARGS = []

        self.assertRaises(SystemExit, command.call)
