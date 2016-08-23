"""
Provides basic integrations of THC Hydra
"""
from tools.common import Command
from tools.hydra.parsers import HydraParser


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
        return HydraParser.parse(output)
