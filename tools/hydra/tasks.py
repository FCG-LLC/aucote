import subprocess
import logging as log

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import Vulnerability
from tools.hydra.base import HydraBase


class HydraScriptTask(HydraBase):
    """
    This class is callable
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
        @TODO: Sending to kudu
        """
        try:
            results = self.call(['-L', cfg.get('tools.hydra.loginfile'), '-P', cfg.get('tools.hydra.passwordfile'),
                             str(self._port.node.ip), self.service, ])
        except subprocess.CalledProcessError as e:
            log.warning("Exiting Hydra process")
            return None

        if not results:
            return None

        serializer = Serializer()
        for result in results:
            vuln = Vulnerability()
            vuln.exploit = self.exploits.find('hydra', 'hydra')
            vuln.port = self._port
            vuln.output = str(result)

            log.debug('Found vulnerability: port=%s exploit=%s output=%s', vuln.port, vuln.exploit.id, vuln.output)
            msg = serializer.serialize_port_vuln(vuln.port, vuln)
            self.kudu_queue.send_msg(msg)
        return results