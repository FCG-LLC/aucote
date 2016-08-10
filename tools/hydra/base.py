from aucote_cfg import cfg
from tools.common import Command
from tools.hydra.structs import HydraResults


class HydraBase(Command):
    COMMON_ARGS = ('-L', cfg.get('tools.hydra.loginfile'), '-P', cfg.get('tools.hydra.passwordfile'))
    NAME = 'hydra'

    SUPORTED_SERVICES = ['asterisk', 'cisco', 'cisco-enable', 'cvs', 'firebird', 'ftp', 'ftps', 'http-get', 'http-post',
                         'http-head', 'https-get', 'https-post', 'https-head', 'http-get-form', 'http-post-form',
                         'https-get-form', 'https-post-form', 'http-proxy', 'http-proxy-urlenum', 'icq', 'imap',
                         'imaps', 'irc', 'ldap2', 'ldap2s', 'ldap3', 'ldap3s', 'ldap3-cram', 'ldap3-crammd5s',
                         'ldap3-digestmd5', 'ldap3-digestmd5s', 'mssql', 'mysql', 'nntp', 'oracle-listener',
                         'oracle-sid', 'pcanywhere', 'pcnfs', 'pop3', 'pop3s', 'postgres', 'rdp', 'redis', 'rexec',
                         'rlogin', 'rsh', 'rtsp', 's7-300', 'sip', 'smb', 'smtp', 'smtps', 'smtp-enum', 'snmp',
                         'socks5', 'ssh', 'sshkey', 'svn', 'teamspeak', 'telnet', 'telnets', 'vmauthd', 'vnc', 'xmpp']

    def parser(cls, output):
        return HydraResults(output)


class HydraScript(HydraBase):

    def __init__(self, port):
        self._port = port

    def __call__(self):
        result = self.call([str(self._port.node.ip), self._port.service_name, ])

        a = 3
        pass