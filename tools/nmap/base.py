"""
This module contains base nmap classes

"""
from tools.common.command import CommandXML


class NmapBase(CommandXML):
    """
    Base for all classes using nmap application.

    """
    COMMON_ARGS = ('-n', '--privileged', '-oX', '-', '-T4')
    NAME = 'nmap'


class NmapScript(object):
    """
    Represents nmap script

    """
    def __init__(self, port, exploit, name=None, args=None):
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

    def get_result(self, script):
        """
        Abstract method for getting results of script execution

        Args:
            script (ElementTree.Element):

        Returns:

        """
        raise NotImplementedError


class VulnNmapScript(NmapScript):
    """
    Represents Vulnerability script

    """
    @classmethod
    def get_result(cls, script):
        """
        Gets result of script execution. Looks for VULNERABLE string in script output

        Args:
            script (ElementTree.Element):

        Returns:
            str|None

        """
        table = script.find('table')
        if table is None:
            return None  # no data, probably no response from server, so no problem detected
        state = table.find("./elem[@key='state']").text
        if state not in ('VULNERABLE', 'LIKELY VULNERABLE'):
            return None  # TODO: add likelihood to vulnerability
        return script.get('output').strip()


class InfoNmapScript(NmapScript):
    """
    Represents non Vulnerability script

    """
    @classmethod
    def get_result(cls, script):
        """
        Returns script output. Doesn't look for any keyword

        Args:
            script (ElementTree.Element):

        Returns:
            str|None

        """
        if script is None:
            return None
        return script.get('output').strip()
