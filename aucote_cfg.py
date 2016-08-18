'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
from utils import Config

#default values
_DEFAULT = {
    'logging':{
        'file': lambda: path.join(path.dirname(__file__), 'aucote.log'),
        'level': 'info',
        'max_file_size': 10*1024*1024,
        'max_files': 5,
        'format': '%(levelname)s %(asctime)s %(threadName)s: %(message)s'
    },
    'database': {
        'migration':{
            'path': lambda: path.join(path.dirname(__file__), 'migrations'),
        },
        'credentials':{
            'port': 5432
        }
    },
    'topdis':{
        'api': {
            'host': 'localhost',
            'port': 1234
        }
    },
    'tools':{
        'nmap':{
            'cmd': 'nmap'
        },
        'masscan': {
            'cmd': 'masscan',
            'args': ''
        },
        'hydra': {
            'cmd': 'hydra',
            'loginfile': 'static/logins.hydra.txt',
            'passwordfile': 'static/passwords.hydra.txt',
            'enable': True,
            'services': ['asterisk', 'cisco', 'cisco-enable', 'cvs', 'firebird', 'ftp', 'ftps', 'http-get', 'http-post',
                         'http-head', 'https-get', 'https-post', 'https-head', 'http-get-form', 'http-post-form',
                         'https-get-form', 'https-post-form', 'http-proxy', 'http-proxy-urlenum', 'icq', 'imap',
                         'imaps', 'irc', 'ldap2', 'ldap2s', 'ldap3', 'ldap3s', 'ldap3-cram', 'ldap3-crammd5s',
                         'ldap3-digestmd5', 'ldap3-digestmd5s', 'mssql', 'mysql', 'nntp', 'oracle-listener',
                         'oracle-sid', 'pcanywhere', 'pcnfs', 'pop3', 'pop3s', 'postgres', 'rdp', 'redis', 'rexec',
                         'rlogin', 'rsh', 'rtsp', 's7-300', 'sip', 'smb', 'smtp', 'smtps', 'smtp-enum', 'snmp',
                         'socks5', 'ssh', 'sshkey', 'svn', 'teamspeak', 'telnet', 'telnets', 'vmauthd', 'vnc', 'xmpp']
        }
    },
    'service': {
        'scans': {
            'period': '12h',
            'threads': 10,
            'ports': '0-65535,U:0-65535',
            'rate': 1000,
        },
        "api":{
            'v1': {
                'host': '0.0.0.0',
                'port': 1235
            }
        }
    }
}

#global cfg
cfg = Config(_DEFAULT)


def load(file_name):
    '''
    Initializes this module.
    Needs to be called before other functions are used.
    '''

    if file_name is None:
        #by default search for "confg.yaml" in application dir
        file_name = path.join(path.dirname(__file__), 'aucote_cfg.yaml')
    #at this point logs do not work, print info to stdout
    print("Reading configuration from file:", file_name)
    cfg.load(file_name, _DEFAULT)
