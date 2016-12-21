import datetime
from unittest import TestCase

import pytz

from utils.time import parse_period, parse_time, parse_time_to_timestamp


class TimeTest(TestCase):
    def test_parse_period(self):
        result = parse_period('1d2h3m4s')
        self.assertEqual(result, datetime.timedelta(1, 7384).total_seconds())

    def test_empty_parse_period(self):
        result = parse_period('')
        self.assertEqual(result, datetime.timedelta(0).total_seconds())

    def test_parse_time_to_timestamp(self):
        when = '2016-05-04T15:32:18' # ISO extended without datetime, should default to UTC.
        result = parse_time_to_timestamp(when)
        expected = datetime.datetime(2016, 5, 4, 15, 32, 18, tzinfo=pytz.utc).timestamp()
        self.assertEqual(result, expected)

    def test_parse_time(self):
        when = '2016-05-04T15:32:18' # ISO extended without datetime, should default to UTC.
        result = parse_time(when)
        expected = datetime.datetime(2016, 5, 4, 15, 32, 18, tzinfo=pytz.utc)
        self.assertEqual(result, expected)
