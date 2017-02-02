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
        self.current_exploits = exploits

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

    def get_info(self):
        return {
            'port': str(self._port),
            'exploits': [exploit.name for exploit in self.current_exploits]
        }

    def get_vulnerabilities(self, results):
        """
        Gets vulnerabilities based upon results

        Args:
            results(list): list of AucoteHttpHeaderResult

        Returns:
            list: list of Vulneravbilities

        """
        raise NotImplementedError
