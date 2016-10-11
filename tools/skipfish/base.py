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

    @classmethod
    def parse(cls, output):
        """
        Args:
            output: stdout of command execution

        Returns: SkipfishIssues object

        """
        return SkipfishOutputParser.parse(output)
