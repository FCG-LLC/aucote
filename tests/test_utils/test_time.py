import datetime
from unittest import TestCase
from unittest.mock import patch

import pytz

from utils.time import parse_period, parse_time, parse_time_to_timestamp, time_str, parse_timestamp_to_time


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

    def test_time_str(self):
        when = datetime.datetime(2016, 5, 4, 15, 32, 18)
        result = time_str(when)
        expected = '2016-05-04T15:32:18+00:00'
        self.assertEqual(result, expected)

    def test_parse_timestamp_to_time(self):
        result = parse_timestamp_to_time(12)
        expected = '1970-01-01T00:00:12+00:00'
        self.assertEqual(result, expected)

    def test_parsers(self):
        timestamp = 73
        self.assertEqual(parse_time_to_timestamp(parse_timestamp_to_time(timestamp)), timestamp)