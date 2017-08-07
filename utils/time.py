"""
Provides time related classes and functions
"""
from datetime import timedelta, datetime

import pytz
from dateutil import parser

_MARKERS = {
    'd': 'days',
    'h': 'hours',
    'm': 'minutes',
    's': 'seconds'
}


def parse_period(txt):
    """
    Parser time period to number of seconds

    Args:
        txt (str): period string

    Returns:
        int

    """
    values = {}
    while txt:
        for num, marker in enumerate(txt):
            if marker in _MARKERS:
                values[_MARKERS[marker]] = int(txt[:num])
                txt = txt[num+1:]
                break

    return timedelta(**values).total_seconds()


def parse_time(txt):
    """
    Parses time to datetime object

    Args:
        txt (str): date in string representation

    Returns:
        datetime.datetime

    """
    result = parser.parse(txt)
    #if there is no timezone info, assume utc
    if result.tzinfo is None:
        result = result.replace(tzinfo=pytz.utc)
    return result


def parse_time_to_timestamp(txt):
    """
    Parses date to timestamp

    Args:
        txt (str): date in string representation

    Returns:
        float

    """
    return parse_time(txt).timestamp()


def time_str(date):
    """
    By default datetime doesn't have time information and we need to clearly return everything in UTC

    Args:
        date:

    Returns:
        str

    """
    if date.tzinfo is None:
        date = date.replace(tzinfo=pytz.utc)
    return date.isoformat()


def parse_timestamp_to_time(timestamp):
    """
    Parses timestamp to ISO date string

    Args:
        timestamp:

    Returns:
        str

    """
    return time_str(datetime.utcfromtimestamp(timestamp))
