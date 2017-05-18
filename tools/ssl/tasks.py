"""
Tasks of testssl integration

"""
from structs import Vulnerability
from tools.common.command_task import CommandTask
from tools.ssl.base import SSLBase
from tools.ssl.structs import SSLSeverity
import logging as log


class SSLScriptTask(CommandTask):
    """
    Task responsible for executing the testssl

    """

    def __init__(self, *args, **kwargs):
        super().__init__(command=SSLBase(), raise_error=False, *args, **kwargs)

    def prepare_args(self):
        return [str(self._port.node.ip)]

    def _get_vulnerabilities(self, results):
        log.debug(results.with_severity_le(SSLSeverity.WARN).output)
        return [Vulnerability(exploit=self.exploit, port=self._port,
                              output=results.with_severity_ge(SSLSeverity.LOW).output)]
