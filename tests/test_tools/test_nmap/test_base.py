from unittest import TestCase
from unittest.mock import Mock, MagicMock

from structs import Vulnerability
from tools.nmap.base import NmapBase, NmapScript, VulnNmapScript, InfoNmapScript
import xml.etree.ElementTree as ET


class NmapBaseTest(TestCase):

    SCRIPT_XML = '''<?xml version="1.0"?>
    <script output="">
    </script>'''

    def setUp(self):
        self.executor = MagicMock()
        self.base = NmapBase(executor=self.executor)

    def test_create(self):
        self.assertEqual(self.base.executor, self.executor)

class NmapScriptTest(TestCase):
    SCRIPT_XML = '''<?xml version="1.0"?>
    <script output="">
    </script>
    '''
    def setUp(self):
        self.port = Mock()
        self.exploit = Mock()
        self.name = 'test'
        self.args='test_args'
        self.ns = NmapScript(self.port, self.exploit, name=self.name, args=self.args)

    def test_handle_no_vuln(self):
        script = ET.fromstring(self.SCRIPT_XML)
        vuln_mock = MagicMock()
        self.ns.get_vulnerability = MagicMock(return_value=vuln_mock)
        vuln = self.ns.handle(script)
        self.assertEqual(vuln, vuln_mock)

    def test_get_vulnerability(self):
        self.assertRaises(NotImplementedError, self.ns.get_vulnerability, None)


class VulnNmapScriptTest(TestCase):
    def setUp(self):
        self.script = VulnNmapScript(exploit=MagicMock(), port=MagicMock())

    def test_get_vulnerability_empty(self):
        script = MagicMock()
        script.find.return_value = None

        result = self.script.get_vulnerability(script)

        self.assertEqual(result, None)

    def test_get_vulnerability_not_vulnerable(self):
        state = MagicMock()
        state.text = 'None'
        table = MagicMock()
        table.find.return_value = state
        script = MagicMock()
        script.find.return_value = state

        result = self.script.get_vulnerability(script)

        self.assertEqual(result, None)

    def test_get_vulnerability_vulnerable(self):
        state = MagicMock()
        state.text = 'VULNERABLE'
        table = MagicMock()
        table.find.return_value = state
        script = MagicMock()
        script.find.return_value = table

        result = self.script.get_vulnerability(script)

        self.assertIsInstance(result, Vulnerability)


class InfoNmapScriptTest(TestCase):
    def setUp(self):
        self.script = InfoNmapScript(exploit=MagicMock(), port=MagicMock())

    def test_get_vulnerability_empty(self):
        result = self.script.get_vulnerability(None)

        self.assertIsInstance(result, Vulnerability)