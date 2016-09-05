import subprocess
import logging as log

import time

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import Vulnerability
from tools.skipfish.base import SkipfishBase


class SkipfishScanTask(SkipfishBase):
    """
    This is task for Skipfish tool. Call skipfish and parse output
    """
    def __init__(self, port, *args, **kwargs):
        """
        Initialize variables
        """
        super().__init__(*args, **kwargs)
        self._port = port

    def __call__(self):
        """
        Call command, parse output and send to kudu_queue
        """
        args = ['-m', str(cfg.get('tools.skipfish.threads')), '-k', cfg.get('tools.skipfish.limit')]
        args.extend(['-o', 'tmp/skipfish_{0}'.format(time.time()),
                     "{0}://{1}:{2}/".format(self._port.service_name, self._port.node.ip, self._port.number)])

        try:
            results = self.call(args)
        except subprocess.CalledProcessError as exception:
            log.warning("Exiting process", exc_info=exception)
            return None

        serializer = Serializer()

        if not results:
            return results

        vuln = Vulnerability()
        vuln.exploit = self.exploits.find('skipfish', 'skipfish')
        vuln.port = self._port
        
        vuln.output = str(results)

        log.debug('Found vulnerability: port=%s exploit=%s output=%s', vuln.port, vuln.exploit.id, vuln.output)
        msg = serializer.serialize_port_vuln(vuln.port, vuln)
        self.kudu_queue.send_msg(msg)
        return results
