"""
Contains all tasks related to the Skipfish tool

"""
import subprocess
import time
import logging as log

from aucote_cfg import cfg
from structs import Vulnerability, Scan
from tools.skipfish.base import SkipfishBase
from utils.task import Task


class SkipfishScanTask(Task):
    """
    This is task for Skipfish tool. Call skipfish and parse output

    """

    def __init__(self, port, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            *args:
            **kwargs:

        """
        super().__init__(*args, **kwargs)
        self._port = port
        self.exploit = self.exploits.find('skipfish', 'skipfish')
        self.command = SkipfishBase()

    def prepare_args(self):
        """
        Prepare aguments for command execution

        Returns:
            list

        """
        args = ['-m', str(cfg.get('tools.skipfish.threads')), '-k', cfg.get('tools.skipfish.limit')]
        args.extend(['-o', '{0}/skipfish_{1}'.format(cfg.get('tools.skipfish.tmp_directory'), time.time()),
                     "{0}://{1}:{2}/".format(self._port.service_name, self._port.node.ip, self._port.number)])
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
