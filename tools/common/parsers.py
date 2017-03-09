"""
Provides set of common parsers

"""
from xml.etree import ElementTree
import logging as log

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
        if not stdout:
            log.warning("No output data for parsing")
            raise NonXMLOutputException()

        try:
            return ElementTree.fromstring(stdout)
        except ElementTree.ParseError:
            raise NonXMLOutputException()
