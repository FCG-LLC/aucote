"""
This module provides tasks related to Hydra

"""
import subprocess
import logging as log
import time

from aucote_cfg import cfg
from structs import Vulnerability, Scan
from tools.hydra.base import HydraBase
from utils.task import Task


class HydraScriptTask(Task, HydraBase):
    """
    This is task for Hydra tool. Call Hydra and parse output

    """

    def __init__(self, port, service, login=True, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port): Port for scanning
            service (str): Service name for scanning
            login (bool): Define if hydra should use login or not
            *args:
            **kwargs:

        """

        super().__init__(*args, **kwargs)
        self._port = port
        self.service = service
        self.login = login
        self.exploit = self.exploits.find('hydra', 'hydra')

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
            results = self.call(args)
        except subprocess.CalledProcessError as exception:
            self._port.scan = Scan(0, 0)
            self.executor.storage.save_scan(exploit=self.exploit, port=self._port)
            log.warning("Exiting process %s ", self.NAME, exc_info=exception)
            return None

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=[self.exploit], port=self._port)

        if not results:
            log.debug("Process %s does not return any result.", self.NAME)
            return None

        self.store_vulnerability(Vulnerability(exploit=self.exploit, port=self._port, output=results))
        return results
