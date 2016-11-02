"""
This module contains structures used by aucote-http-headers tool

"""
import re


class HeaderDefinition(object):
    """
    Definition of header. Defines name of header and how to check it.

    """
    def __init__(self, pattern, obligatory):
        """
        Init variables

        Args:
            pattern (str): Pattern for header value testing
            obligatory (bool): Defines if header is obligatory or not

        """
        self.pattern = pattern
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.obligatory = obligatory


class AucoteHttpHeaderResult(object):
    """
    Result of successful check

    """
    def __init__(self, output, exploit):
        """

        Args:
            output (str): checks output
            exploit (Exploit): exploit handler

        """
        self.output = output
        self.exploit = exploit

    def __eq__(self, other):
        """
        Check if two objects are equal
        Args:
            other (AucoteHttpHeaderResult):

        Returns:
            bool

        """
        return isinstance(other, AucoteHttpHeaderResult) and self.output == other.output \
               and self.exploit == other.exploit

    def __ne__(self, other):
        """
        Check if two objects are not equal
        Args:
            other (AucoteHttpHeaderResult):

        Returns:
            bool

        """
        return not self == other
