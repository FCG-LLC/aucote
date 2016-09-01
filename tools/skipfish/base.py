"""
Provides basic integrations of Skipfish
"""
from tools.common import Command
from tools.skipfish.parsers import SkipfishResultsParser, SkipfishOutputParser


class SkipfishBase(Command):
    """
    Skipfish base class
    """
    COMMON_ARGS = ('-u',)
    NAME = 'skipfish'

    @classmethod
    def parser(cls, output):
        """
        Parse output and return HydraResults object
        """
        return SkipfishOutputParser.parse(output)
