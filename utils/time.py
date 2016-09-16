"""
Provides time related classes and functions
"""
from datetime import timedelta

_MARKERS = {
    'd': 'days',
    'h': 'hours',
    'm': 'minutes',
    's': 'seconds'
}


def parse_period(txt):
    """
    parses time period
    """
    values = {}
    while txt:
        for num, marker in enumerate(txt):
            if marker in _MARKERS:
                values[_MARKERS[marker]] = int(txt[:num])
                txt = txt[num+1:]
                break

    return timedelta(**values).total_seconds()
