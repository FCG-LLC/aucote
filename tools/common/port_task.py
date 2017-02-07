"""
This module contains task related to port.

"""
import time

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
        with self._lock:
            return self._current_exploits

    @current_exploits.setter
    def current_exploits(self, val):
        with self._lock:
            self._current_exploits = val

    @property
    def port(self):
        with self._lock:
            return self._port
