"""
Provides configuration for tools. Configuration is implicit and shouldn't be modified by end-user.
"""

from tools.hydra.tool import HydraTool
from tools.nmap.tool import NmapTool

EXECUTOR_CONFIG = {
    'apps': {
        'nmap': {
            'class': NmapTool,
            'services': {
                'http-slowloris-check': {
                    'args': 'http-slowloris.threads=500,http-slowloris.timeout=200'
                },
                'smtp-vuln-cve2010-4344': {
                    'args': 'smtp-vuln-cve2010-4344.exploit'
                },
                'smtp-vuln-cve2011-1720': {
                    'args': 'smtp.domain=test'
                }
            }
        },
        'hydra': {
            'class': HydraTool,
            'services': {'asterisk', 'cisco', 'cisco-enable', 'cvs', 'firebird', 'ftp', 'ftps', 'http', 'https',
                         'http-post', 'http-head', 'https-get', 'https-post', 'https-head', 'http-get-form',
                         'http-post-form', 'https-get-form', 'https-post-form', 'http-proxy', 'http-proxy-urlenum',
                         'icq', 'imap', 'imaps', 'irc', 'ldap2', 'ldap2s', 'ldap3', 'ldap3s', 'ldap3-cram',
                         'ldap3-crammd5s', 'ldap3-digestmd5', 'ldap3-digestmd5s', 'mssql', 'mysql', 'nntp',
                         'oracle-listener', 'oracle-sid', 'pcanywhere', 'pcnfs', 'pop3', 'pop3s', 'postgres', 'rdp',
                         'redis', 'rexec', 'rlogin', 'rsh', 'rtsp', 's7-300', 'sip', 'smb', 'smtp', 'smtps',
                         'smtp-enum', 'snmp', 'socks5', 'ssh', 'sshkey', 'svn', 'teamspeak', 'telnet', 'telnets',
                         'vmauthd', 'vnc', 'xmpp'},
            'mapper': {
                'http': 'http-get',
                'https': 'https-get',
                'microsoft-ds': 'smb',
                'microsoft-ssn': 'smb',
                'microsoft-sn': 'smb',
            },
        }
    }
}