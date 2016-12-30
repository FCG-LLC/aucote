"""
Contains base class for tasks, which run shell command

"""
import subprocess
import time
import logging as log

from structs import Scan, Vulnerability
from tools.common.port_task import PortTask


class CommandTask(PortTask):
    """
    Task which runs shell command

    """
    def __init__(self, command, *args, **kwargs):
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
        self.command = command

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
            self.executor.storage.save_scans(exploits=self.current_exploits, port=self._port)
            log.warning("Exiting process %s ", self.command.NAME, exc_info=exception)
            return None

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

        if not results:
            log.debug("Process %s does not return any result.", self.command.NAME)
            return None

        vulnerabilities = self._get_vulnerabilities(results)
        log.info("Found %i vulnerabilities for %s", len(vulnerabilities), str(self._port))

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                self.store_vulnerability(vulnerability)

        return results

    def _get_vulnerabilities(self, results):
        """
        Gets vulnerabilities based upon results

        Args:
            results:

        Returns:
            list

        """
        return [Vulnerability(exploit=self.exploit, port=self._port, output=results)]
