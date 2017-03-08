"""
Provides set of common parsers

"""
from xml.etree import ElementTree

from utils.exceptions import NonXMLOutputException


class Parser(object):
    """
    Return output

    """
    @classmethod
    def parse(cls, output):
        """
        Return output

        Args:
            output (str):

        Returns:
            str

        """
        return output


class XMLParser(object):
    """
    Parser for XML output

    """
    @classmethod
    def parse(cls, output):
        """
        Treats output as XML and return ElementTree object

        Args:
            output (str):

        Returns:
            ElementTree.Element|None

        """
        if not output:
            raise NonXMLOutputException()

        try:
            return ElementTree.fromstring(output)
        except ElementTree.ParseError:
            raise NonXMLOutputException()
