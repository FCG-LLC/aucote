import datetime
from unittest import TestCase

from utils.time import parse_period


class TimeTest(TestCase):
    def test_parse_period(self):
        result = parse_period('1d2h3m4s')
        self.assertEqual(result, datetime.timedelta(1, 7384))