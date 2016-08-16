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
        self.base = NmapBase(self.executor)

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
        self.ns = NmapScript(self.port, self.exploit)

    def test_handle_no_vuln(self):
        script = ET.fromstring(self.SCRIPT_XML)
        self.ns.get_vulnerability = MagicMock(return_value=None)
        vuln = self.ns.handle(script)
        self.assertIsNone(vuln)
