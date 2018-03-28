"""
Contains base class for tasks, which run shell command

"""
import subprocess
import time
import logging as log

from tornado import gen

from aucote_cfg import cfg
from structs import Scan, Vulnerability
from tools.common.port_task import PortTask
from utils.exceptions import StopCommandException


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

    async def __call__(self):
        """
        Call command, parse output and stores vulnerabilities

        Returns:

        """
        try:
            args = self.prepare_args()
        except StopCommandException:
            log.exception("Cannot execute command")
            return None

        timeout = cfg['tools.{}.timeout'.format(self.command.NAME)]

        try:
            results = await self.command.async_call(args, timeout=timeout)
        except subprocess.CalledProcessError:
            self._port.scan = Scan(0, 0)
            self.aucote.storage.save_security_scans(exploits=self.current_exploits, port=self._port, scan=self._scan)
            log.error("Exiting process %s", self.command.NAME)
            return None
        except gen.TimeoutError:
            return None

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

        if results is None:
            return None

        vulnerabilities = self._get_vulnerabilities(results)
        self.store_vulnerabilities(vulnerabilities)

        return results

    def _get_vulnerabilities(self, results):
        return [Vulnerability(exploit=self.exploit, port=self._port, output=results, context=self.context)]

    def cancel(self):
        if self.command:
            self.command.kill()

        super().cancel()
