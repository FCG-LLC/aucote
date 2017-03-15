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
    def parse(cls, stdout, stderr=None):
        """
        Return output

        Args:
            stdout (str):
            stderr (str):

        Returns:
            str

        """
        return stdout


class XMLParser(Parser):
    """
    Parser for XML output

    """
    @classmethod
    def parse(cls, stdout, stderr=None):
        """
        Treats output as XML and return ElementTree object

        Args:
            stdout (str):
            stderr (str):

        Returns:
            ElementTree.Element|None

        """
        try:
            return ElementTree.fromstring(stdout)
        except ElementTree.ParseError:
            raise NonXMLOutputException()
