from unittest import TestCase

from tools.skipfish.base import SkipfishBase
from tools.skipfish.parsers import SkipfishOutputParser


class SkipfishBaseTest(TestCase):

    def test_parser(self):
        self.assertIsInstance(SkipfishBase.parser, SkipfishOutputParser)