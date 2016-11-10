"""
Provides basic integrations of Skipfish

"""
from tools.common import Command
from tools.skipfish.parsers import SkipfishOutputParser


class SkipfishBase(Command):
    """
    Skipfish base class

    """
    COMMON_ARGS = ('-u',)
    NAME = 'skipfish'

    parser = SkipfishOutputParser
