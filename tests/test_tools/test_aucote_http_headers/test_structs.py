import re
from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open

from tools.aucote_http_headers.structs import HeaderDefinition, AucoteHttpHeaderResult


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


class AucoteHttpHeaderResultTest(TestCase):
    def test_init(self):
        output = 'test_output'
        exploit = 'test_exploit'
        result = AucoteHttpHeaderResult(output=output, exploit=exploit)

        self.assertEqual(result.output, output)
        self.assertEqual(result.exploit, exploit)

    def test_equal(self):
        output = 'test_output'
        exploit = 'test_exploit'
        result = AucoteHttpHeaderResult(output=output, exploit=exploit)
        result_2 = AucoteHttpHeaderResult(output=output, exploit=exploit)

        self.assertEqual(result, result_2)

    def test_nonequal(self):
        output = 'test_output'
        exploit = 'test_exploit'
        output_2 = 'test_output_2'
        exploit_2 = 'test_exploit_2'

        result = AucoteHttpHeaderResult(output=output, exploit=exploit)
        result_2 = AucoteHttpHeaderResult(output=output_2, exploit=exploit_2)

        self.assertNotEqual(result, result_2)