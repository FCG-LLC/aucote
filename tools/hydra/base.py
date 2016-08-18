"""
Provides basic integrations of THC Hydra
"""
import logging as log

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import Vulnerability
from tools.common import Command
from tools.hydra.structs import HydraResults


class HydraBase(Command):
    """
    Hydra base class
    """
    COMMON_ARGS = ('-t', '4')
    NAME = 'hydra'

    SUPORTED_SERVICES = ['asterisk', 'cisco', 'cisco-enable', 'cvs', 'firebird', 'ftp', 'ftps', 'http-get', 'http-post',
                         'http-head', 'https-get', 'https-post', 'https-head', 'http-get-form', 'http-post-form',
                         'https-get-form', 'https-post-form', 'http-proxy', 'http-proxy-urlenum', 'icq', 'imap',
                         'imaps', 'irc', 'ldap2', 'ldap2s', 'ldap3', 'ldap3s', 'ldap3-cram', 'ldap3-crammd5s',
                         'ldap3-digestmd5', 'ldap3-digestmd5s', 'mssql', 'mysql', 'nntp', 'oracle-listener',
                         'oracle-sid', 'pcanywhere', 'pcnfs', 'pop3', 'pop3s', 'postgres', 'rdp', 'redis', 'rexec',
                         'rlogin', 'rsh', 'rtsp', 's7-300', 'sip', 'smb', 'smtp', 'smtps', 'smtp-enum', 'snmp',
                         'socks5', 'ssh', 'sshkey', 'svn', 'teamspeak', 'telnet', 'telnets', 'vmauthd', 'vnc', 'xmpp']

    @classmethod
    def parser(cls, output):
        """
        Parse output and return HydraResults object
        """
        return HydraResults(output)


class HydraScriptTask(HydraBase):
    """
    This class is callable
    """
    def __init__(self, executor, port):
        """
        Initialize variables
        """
        super().__init__(executor=executor)
        self._port = port

    def __call__(self):
        """
        Call command, parse output and send to kudu_queue
        @TODO: Sending to kudu
        """
        results = self.call(['-L', cfg.get('tools.hydra.loginfile'), '-P', cfg.get('tools.hydra.passwordfile'),
                             str(self._port.node.ip), self._port.service_name, ])
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
