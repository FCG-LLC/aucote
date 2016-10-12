"""
Contains all tasks related to the Skipfish tool

"""
import subprocess
import time
import logging as log

from aucote_cfg import cfg
from structs import Vulnerability, Scan
from tools.common.command_task import CommandTask
from tools.skipfish.base import SkipfishBase


class SkipfishScanTask(CommandTask):
    """
    This is task for Skipfish tool. Call skipfish and parse output

    """

    def __init__(self, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            *args:
            **kwargs:

        """
        super().__init__(command=SkipfishBase(), *args, **kwargs)

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
