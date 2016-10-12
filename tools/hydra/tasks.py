"""
This module provides tasks related to Hydra

"""
import subprocess
import logging as log
import time

from aucote_cfg import cfg
from structs import Vulnerability, Scan
from tools.common.command_task import CommandTask
from tools.hydra.base import HydraBase
from utils.task import Task


class HydraScriptTask(CommandTask):
    """
    This is task for Hydra tool. Call Hydra and parse output

    """

    def __init__(self, service, login=True, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port): Port for scanning
            service (str): Service name for scanning
            login (bool): Define if hydra should use login or not
            *args:
            **kwargs:

        """

        super().__init__(command=HydraBase(), *args, **kwargs)
        self.service = service
        self.login = login

    def prepare_args(self):
        """
        Prepare aguments for command execution

        Returns:
            list

        """
        args = []
        if self.login:
            args.extend(['-L', cfg.get('tools.hydra.loginfile')])
        args.extend(['-P', cfg.get('tools.hydra.passwordfile'), '-s', str(self._port.number), str(self._port.node.ip),
                     self.service, ])
        return args

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
