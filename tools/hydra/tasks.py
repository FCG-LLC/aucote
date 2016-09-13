import subprocess
import logging as log

from aucote_cfg import cfg
from structs import Vulnerability
from tools.hydra.base import HydraBase


class HydraScriptTask(HydraBase):
    """
    This is task for Hydra tool. Call Hydra and parse output
    """

    def __init__(self, executor, port, service, login=True):
        """
        Initialize variables
        """

        super().__init__(executor=executor)
        self._port = port
        self.service = service
        self.login = login

    def __call__(self):
        """
        Call command, parse output and store vulnerability
        """

        args = []
        if self.login:
            args.extend(['-L', cfg.get('tools.hydra.loginfile')])
        args.extend(['-P', cfg.get('tools.hydra.passwordfile'), '-s', str(self._port.number), str(self._port.node.ip),
                     self.service, ])

        try:
            results = self.call(args)
        except subprocess.CalledProcessError as exception:
            log.warning("Exiting Hydra process", exc_info=exception)
            return None

        if not results:
            log.debug("Hydra does not find any password.")
            return None

        self.store_vulnerability(Vulnerability(exploit=self.exploits.find('hydra', 'hydra'), port = self._port,
                                               output=results))
        return results
