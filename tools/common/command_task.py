"""
Contains base class for tasks, which run shell command

"""
import subprocess
import time
import logging as log

from structs import Scan, Vulnerability
from utils.task import Task


class CommandTask(Task):
    """
    Task which runs shell command

    """
    def __init__(self, port, exploit, command, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            exploit (Exploit):
            command (Command):
            *args:
            **kwargs:

        """
        super().__init__(*args, **kwargs)
        self._port = port
        self.command = command
        self.exploit = exploit

    @classmethod
    def prepare_args(cls):
        """
        Prepare arguments for call command.

        Returns:
            list

        """
        raise NotImplementedError

    def __call__(self):
        """
        Call command, parse output and stores vulnerabilities

        Returns:

        """
        args = self.prepare_args()

        try:
            results = self.command.call(args)
        except subprocess.CalledProcessError as exception:
            self._port.scan = Scan(0, 0)
            self.executor.storage.save_scan(exploit=self.exploit, port=self._port)
            log.warning("Exiting process %s ", self.command.NAME, exc_info=exception)
            return None

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=[self.exploit], port=self._port)

        if not results:
            log.debug("Process %s does not return any result.", self.command.NAME)
            return None

        self.store_vulnerability(Vulnerability(exploit=self.exploit, port=self._port, output=results))
        return results
