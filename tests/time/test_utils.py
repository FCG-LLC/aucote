import datetime
from unittest import TestCase

ZERO = datetime.timedelta(0)

# A UTC class.

class UTC(datetime.tzinfo):
    """UTC"""

    @classmethod
    def utcoffset(cls, dt=None):
        return ZERO

    @classmethod
    def tzname(cls, dt=None):
        return "UTC"

    @classmethod
    def dst(cls, dt=None):
        return ZERO