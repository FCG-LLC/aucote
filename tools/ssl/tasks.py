"""
Tasks of testssl integration

"""
import logging as log
from structs import Vulnerability
from tools.common.command_task import CommandTask
from tools.ssl.base import SSLBase
from tools.ssl.structs import SSLSeverity


class SSLScriptTask(CommandTask):
    """
    Task responsible for executing the testssl

    """

    def __init__(self, *args, **kwargs):
        super().__init__(command=SSLBase(), *args, **kwargs)

    def prepare_args(self):
        target = "{0}:{1}".format(str(self._port.node.ip), str(self._port.number))
        if self._port.protocol in ['ftp', 'smtp', 'pop3', 'imap', 'xmpp', 'telnet', 'ldap']:
            return ['-t', self._port.protocol, target]
        return [target]

    def _get_vulnerabilities(self, results):
        log.debug(results.with_severity_le(SSLSeverity.WARN).output)
        return [Vulnerability(exploit=self.exploit, port=self._port,
                              output=results.with_severity_ge(SSLSeverity.LOW).output)]
