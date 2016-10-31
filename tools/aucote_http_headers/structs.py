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
            name (str):
            pattern (str): Pattern for header value testing
            exploit (Exploit): Exploit related to header

        """
        self.pattern = pattern
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.obligatory = obligatory