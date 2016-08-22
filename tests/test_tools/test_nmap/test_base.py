from unittest import TestCase
from unittest.mock import Mock, MagicMock
from tools.nmap.base import NmapBase, NmapScript
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
