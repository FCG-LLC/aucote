from unittest import TestCase
from unittest.mock import patch, MagicMock

from tools.ssl.parsers import SSLParser
from tools.ssl.structs import SSLResults


class SSLParserTest(TestCase):
    FILE_CONTENT = """, {
              "id"           : "service",
              "ip"           : "10.12.1.24/10.12.1.24",
              "port"         : "443",
              "severity"     : "INFO",
              "finding"      : "Service detected: HTTP"
          }
,         {
              "id"           : "heartbleed",
              "ip"           : "10.12.1.24/10.12.1.24",
              "port"         : "443",
              "severity"     : "OK",
              "cve"          : "CVE-2014-0160",
              "cwe"          : "CWE-119",
              "finding"      : "Heartbleed: not vulnerable , timed out"
          }"""

    def setUp(self):
        self.filename = MagicMock(name='test_filename')
        self.parser = SSLParser(self.filename)

    def test_init(self):
        self.assertEqual(self.parser.tempfile, self.filename)

    @patch('tools.ssl.parsers.Path')
    def test_parse(self, mock_path):
        mock_path.return_value.read_text.return_value = self.FILE_CONTENT

        result = self.parser.parse()
        self.assertIsInstance(result, SSLResults)
        self.assertEqual(len(result.results), 2)
