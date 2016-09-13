from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.skipfish.base import SkipfishBase


class SkipfishBaseTest(TestCase):

    @patch('tools.skipfish.parsers.SkipfishOutputParser.parse')
    def test_parser(self, mock_parser):
        expected = MagicMock
        mock_parser.return_value = expected
        result = SkipfishBase.parser(MagicMock())
        self.assertEqual(result, expected)