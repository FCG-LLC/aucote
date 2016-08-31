"""
Provides basic integrations of Skipfish
"""
from tools.common import Command
from tools.skipfish.parsers import SkipfishResultsParser


class SkipfishBase(Command):
    """
    Skipfish base class
    """
    COMMON_ARGS = ('-u', '-m', '2')
    NAME = 'skipfish'
