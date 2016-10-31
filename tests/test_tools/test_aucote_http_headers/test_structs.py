import re
from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open

from tools.aucote_http_headers.structs import HeaderDefinition, HeaderDefinitions


class HeaderDefinitionTest(TestCase):
    def setUp(self):
        self.name = 'test_name'
        self.pattern = ''
        self.regex = re.compile(self.pattern, re.IGNORECASE)
        self.description = 'desc_test'
        self.exploit = MagicMock()
        self.definition = HeaderDefinition(name=self.name, pattern=self.pattern, exploit=self.exploit)

    def test_init(self):
        self.assertEqual(self.definition.name, self.name)
        self.assertEqual(self.definition.pattern, self.pattern)
        self.assertEqual(self.definition.regex, self.regex)


class HeaderDefinitionsTest(TestCase):
    CSV_PARSED = [['name', 'pattern'],
                  ['test_name', 'test_pattern']]

    @patch('tools.aucote_http_headers.structs.HeaderDefinitions.read', MagicMock())
    def test_iter(self):
        exploits = MagicMock()
        defs = HeaderDefinitions(filename='test', exploits=exploits)
        header_def = HeaderDefinition(name='test_name', pattern='test_pattern', exploit=exploits.find())
        defs._headers = [header_def]

        for header in defs:
            self.assertEqual(header, header_def)

    @patch('builtins.open', mock_open(read_data=""))
    @patch('csv.reader', MagicMock(return_value=CSV_PARSED))
    @patch('tools.aucote_http_headers.structs.HeaderDefinition')
    def test_read(self, mock_def):
        exploits = MagicMock()
        HeaderDefinitions(filename='test', exploits=exploits)
        mock_def.called_once_with(name='test_name', pattern='test_pattern', exploit=exploits.find.return_value)
        exploits.find.called_once_with('aucote-http-headers', 'test_name')