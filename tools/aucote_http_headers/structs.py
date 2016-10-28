"""
This module contains structures used by aucote-http-headers tool

"""
import csv
import re


class HeaderDefinition(object):
    """
    Definition of header. Defines name of header and how to check it.

    """
    def __init__(self, name, pattern, description):
        """
        Init variables

        Args:
            name (str):
            pattern (str): Pattern for header value testing
            description (str): Description of header, e.g. usage

        """
        self.pattern = pattern
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.name = name
        self.description = description


class HeaderDefinitions(object):
    def __init__(self, filename):
        self._headers = self.read(filename)

    @classmethod
    def read(cls, filename):
        """
        Reads Headers Definition from csv file

        Args:
            filename (str):
            filename (str):

        Returns:
            list
        """
        return_value = []

        with open(filename, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=';', quotechar='"')
            for num, row in enumerate(reader):
                if num == 0:
                    continue
                return_value.append(HeaderDefinition(name=row[0], pattern=row[1], description=row[2]))
        return return_value

    def __iter__(self):
        """
        Implements iteration over headers in collection

        Returns:
            HeaderDefinition

        """
        return iter(self._headers)
