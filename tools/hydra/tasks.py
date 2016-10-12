"""
This module provides tasks related to Hydra

"""
from aucote_cfg import cfg
from tools.common.command_task import CommandTask
from tools.hydra.base import HydraBase


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
