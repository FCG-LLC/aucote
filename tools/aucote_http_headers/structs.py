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
