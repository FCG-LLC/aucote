"""
This module contains base nmap classes

"""
from tools.common.command import Command
from tools.common.parsers import XMLParser


class NmapBase(Command):
    """
    Base for all classes using nmap application.

    """
    COMMON_ARGS = ('-n', '--privileged', '-oX', '-', '-T4')
    NAME = 'nmap'
    parser = XMLParser()


class NmapScript(object):
    """
    Represents nmap script

    """
    def __init__(self, port, exploit, parser, name=None, args=None):
        """
        Init variables

        Args:
            port (Port):
            exploit (exploit):
            name (str):
            args (list):

        """
        self.exploit = exploit
        self.port = port
        self.name = name
        self.args = args
        self.parser = parser

    def get_result(self, script):
        """
        Abstract method for getting results of script execution

        Args:
            script (ElementTree.Element):

        Returns:

        """
        return self.parser.parse(script)
