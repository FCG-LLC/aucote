import re
from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open

from tools.aucote_http_headers.structs import HeaderDefinition


class HeaderDefinitionTest(TestCase):
    def setUp(self):
        self.name = 'test_name'
        self.pattern = ''
        self.regex = re.compile(self.pattern, re.IGNORECASE)
        self.description = 'desc_test'
        self.exploit = MagicMock()
        self.definition = HeaderDefinition(pattern=self.pattern, obligatory=True)

    def test_init(self):
        self.assertEqual(self.definition.pattern, self.pattern)
        self.assertEqual(self.definition.regex, self.regex)
        self.assertTrue(self.definition.obligatory)