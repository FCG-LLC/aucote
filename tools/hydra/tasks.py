import subprocess
import logging as log

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import Vulnerability
from tools.hydra.base import HydraBase


class HydraScriptTask(HydraBase):
    """
    This is task for Hydra tool. Call Hydra and parse output
    """
    def __init__(self, executor, port, service):
        """
        Initialize variables
        """
        super().__init__(executor=executor)
        self._port = port
        self.service = service

    def __call__(self):
        """
        Call command, parse output and send to kudu_queue
        """

        try:
            results = self.call(['-L', cfg.get('tools.hydra.loginfile'), '-P', cfg.get('tools.hydra.passwordfile'),
                             '-s', str(self._port.number), str(self._port.node.ip), self.service, ])
        except subprocess.CalledProcessError as exception:
            log.warning("Exiting Hydra process", exc_info=exception)
            return None

        if not results:
            log.debug("Hydra does not find any password.")
            return None

        serializer = Serializer()
        vuln = Vulnerability()
        vuln.exploit = self.exploits.find('hydra', 'hydra')
        vuln.port = self._port
        vuln.output = str(results)

        log.debug('Found vulnerability: port=%s exploit=%s output=%s', vuln.port, vuln.exploit.id, vuln.output)
        msg = serializer.serialize_port_vuln(vuln.port, vuln)
        self.kudu_queue.send_msg(msg)
        return results
