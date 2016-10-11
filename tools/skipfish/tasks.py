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


class SkipfishScanTask(Task, SkipfishBase):
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

    def __call__(self):
        """
        Call command, parse output and send to kudu_queue

        """

        args = ['-m', str(cfg.get('tools.skipfish.threads')), '-k', cfg.get('tools.skipfish.limit')]
        args.extend(['-o', '{0}/skipfish_{1}'.format(cfg.get('tools.skipfish.tmp_directory'), time.time()),
                     "{0}://{1}:{2}/".format(self._port.service_name, self._port.node.ip, self._port.number)])

        try:
            results = self.call(args)
        except subprocess.CalledProcessError as exception:
            self._port.scan = Scan(0, 0)
            self.executor.storage.save_scan(exploit=self.exploit, port=self._port)
            log.warning("Exiting process", exc_info=exception)
            return None

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=[self.exploit], port=self._port)

        if not results:
            return results

        self.store_vulnerability(Vulnerability(exploit=self.exploit, port=self._port, output=results))
        return results
