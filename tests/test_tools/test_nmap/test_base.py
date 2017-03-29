from unittest import TestCase
from unittest.mock import Mock, MagicMock

from tools.nmap.base import NmapBase, NmapScript


class NmapBaseTest(TestCase):

    SCRIPT_XML = '''<?xml version="1.0"?>
    <script output="">
    </script>'''

    def setUp(self):
        self.base = NmapBase()

    def test_init(self):
        self.assertEqual(self.base.NAME, 'nmap')

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
        self.ns = NmapScript(self.port, self.exploit, parser=MagicMock(), name=self.name, args=self.args)

    def test_get_result(self):
        args = MagicMock()
        result = self.ns.get_result(args)
        expected = self.ns.parser.parse.return_value

        self.ns.parser.parse.assert_called_once_with(args)
        self.assertEqual(result, expected)
