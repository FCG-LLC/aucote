"""
This module contains task related to port.

"""
from utils.task import Task


class PortTask(Task):
    """
    Abstract class for exploit-tasks executed on port

    """
    def __init__(self, port, exploits, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            exploit (Exploit):
            *args:
            **kwargs:

        """
        super().__init__(*args, **kwargs)
        self._port = port
        self._current_exploits = exploits

    @property
    def exploit(self):
        """
        Exploit or None if task have more exploits

        Returns:
            Exploit|None

        """
        if len(self.current_exploits) == 1:
            return next(iter(self.current_exploits))
        return None

    def get_vulnerabilities(self, results):
        """
        Gets vulnerabilities based upon results

        Args:
            results(list): list of AucoteHttpHeaderResult

        Returns:
            list: list of Vulneravbilities

        """
        raise NotImplementedError

    @property
    def current_exploits(self):
        """
        List of exploits, which are used by task

        Returns:
            list

        """
        return self._current_exploits[:]

    @current_exploits.setter
    def current_exploits(self, val):
        self._current_exploits = val

    @property
    def port(self):
        """
        Port

        Returns:
            Port

        """
        return self._port
