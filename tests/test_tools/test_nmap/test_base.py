from unittest import TestCase
from unittest.mock import Mock, MagicMock

from tools.nmap.base import NmapBase, NmapScript, VulnNmapScript, InfoNmapScript


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

    def test_get_result(self):
        self.assertRaises(NotImplementedError, self.ns.get_result, None)


class VulnNmapScriptTest(TestCase):
    def setUp(self):
        self.script = VulnNmapScript(exploit=MagicMock(), port=MagicMock())

    def test_get_result_empty(self):
        script = MagicMock()
        script.find.return_value = None

        result = self.script.get_result(script)

        self.assertEqual(result, None)

    def test_get_result_not_vulnerable(self):
        state = MagicMock()
        state.text = 'None'
        table = MagicMock()
        table.find.return_value = state
        script = MagicMock()
        script.find.return_value = state

        result = self.script.get_result(script)

        self.assertEqual(result, None)

    def test_get_result_vulnerable(self):
        state = MagicMock()
        state.text = 'VULNERABLE'
        table = MagicMock()
        table.find.return_value = state
        script = MagicMock()
        script.find.return_value = table
        script.get = MagicMock(return_value='  test   ')
        result = self.script.get_result(script)

        self.assertEqual(result, 'test')


class InfoNmapScriptTest(TestCase):
    def setUp(self):
        self.script = InfoNmapScript(exploit=MagicMock(), port=MagicMock())

    def test_get_result_empty(self):
        result = self.script.get_result(None)

        self.assertFalse(result)

    def test_get_result_vulnerable(self):
        script = MagicMock()
        script.get = MagicMock(return_value='  test   ')
        result = self.script.get_result(script)

        self.assertEqual(result, 'test')
