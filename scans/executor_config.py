"""
Provides configuration for tools. Configuration is implicit and shouldn't be modified by end-user.
"""
from tools.acuote_ad.tool import AucoteActiveDirectory
from tools.aucote_http_headers.structs import HeaderDefinition
from tools.aucote_http_headers.tool import AucoteHttpHeadersTool
from tools.cve_search.tool import CVESearchTool
from tools.hydra.tool import HydraTool
from tools.nmap.parsers import NmapBrutParser, NmapInfoParser
from tools.nmap.tool import NmapTool
from tools.skipfish.tool import SkipfishTool
from tools.whatweb.tool import WhatWebTool
from tools.ssl.tool import SSLTool

EXECUTOR_CONFIG = {
    'apps': {
        'nmap': {
            'class': NmapTool,
            'scripts': {
                'http-slowloris-check': {
                    'args': 'http-slowloris.threads=500,http-slowloris.timeout=200'
                },
                'smtp-vuln-cve2010-4344': {
                    'args': 'smtp-vuln-cve2010-4344.exploit'
                },
                'smtp-vuln-cve2011-1720': {
                    'args': 'smtp.domain=test'
                },
                'http-barracuda-dir-traversal': {
                    'args': 'http-max-cache-size=5000000'
                },
                'dns-zone-transfer': {
                    'args': NmapTool.custom_args_dns_zone_transfer
                },
                'dns-srv-enum': {
                    'args': NmapTool.custom_args_dns_srv_enum,
                    'singular': True
                },
                'http-domino-enum-passwords': {
                    'args': NmapTool.custom_args_http_domino_enum_passwords
                },
                'dns-check-zone': {
                    'args': NmapTool.custom_args_dns_check_zone,
                    'singular': True
                },
                'broadcast-listener': {
                    'singular': True
                },
                'eap-info': {
                    'singular': True
                },
                'broadcast-wpad-discovery': {
                    'singular': True
                },
                'ipmi-brute': {
                    'args': 'userdb=static/nmap/usernames.lst,passdb=static/nmap/passwords.lst',
                    'singular': True,
                    'parser': NmapBrutParser
                },
                'ipmi-dumphashes': {
                    'args': 'userdb=static/nmap/usernames.lst,passdb=static/nmap/passwords.lst,'
                            'dumphashes=1,brute.emptypass=1',
                    'parser': NmapBrutParser
                },
                'supermicro-ipmi-conf': {
                    'args': 'supermicro-ipmi-conf.out=/dev/null'
                },
                'http-trace': {
                    'parser': NmapInfoParser
                },
                'struts2-scan': {
                    'parser': NmapInfoParser,
                    'singular': True,  # http-iis-webdav-vuln, http-slowloris-check, http-webdav-scan,
                                       # http-email-harvest in some way influence on this script
                },
                'smb-vuln-cve2009-3103': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-os-discovery': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-ms06-025': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-ms07-029': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-ms08-067': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-ms10-061': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-regsvc-dos': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-enum-domains': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-enum-sessions': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-enum-shares': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-system-info': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-conficker': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-ms10-054': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-enum-users': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-enum-groups': {
                    'args': NmapTool.custom_args_smb
                },
                'smb-vuln-ms17-010': {
                    'args': NmapTool.custom_args_smb
                }
            },
            'services': {
                'http': {
                    'args': NmapTool.custom_args_http_useragent
                }
            },
            'disable_scripts': {
                'ipmi-brute'
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
                'microsoft-ns': 'smb',
            },
            'without-login': ['redis', 'cisco', 'oracle-listener', 's7-300', 'snmp', 'vnc']
        },
        'skipfish': {
            'class': SkipfishTool,
        },
        'aucote-http-headers': {
            'class': AucoteHttpHeadersTool,
            'loader': None,
            'headers': {
                'x-frame-options':
                    HeaderDefinition(pattern=r'^(deny|SAMEORIGIN)$', obligatory=True),

                'access-control-allow-origin':
                    HeaderDefinition(pattern=r'^((?!\*).)*$', obligatory=False),

                'access-control-allow-methods':
                    HeaderDefinition(pattern=r'', obligatory=False),

                'access-control-allow-headers':
                    HeaderDefinition(pattern=r'', obligatory=False),

                'access-control-max-age':
                    HeaderDefinition(pattern=r'', obligatory=False),

                'content-security-policy':
                    HeaderDefinition(pattern=r'^(?=.*upgrade-insecure-requests)(?=.*reflected-xss).*$',
                                     obligatory=True),

                'content-security-policy-report-only':
                    HeaderDefinition(pattern=r'^(?=.*upgrade-insecure-requests)(?=.*reflected-xss).*$',
                                     obligatory=False),

                'x-content-security-policy':
                    HeaderDefinition(pattern=r'^(?=.*upgrade-insecure-requests)(?=.*reflected-xss).*$',
                                     obligatory=False),

                'content-encoding':
                    HeaderDefinition(pattern=r'^((?!(gzip|deflate)).)*$', obligatory=False),

                'public-key-pins':
                    HeaderDefinition(pattern=r'', obligatory=True),

                'referrer-policy':
                    HeaderDefinition(pattern=r'^((?!(|unsafe-url)).)*$', obligatory=True),

                'strict-transport-security':
                    HeaderDefinition(pattern=r'^((?!max-age=0).)*$', obligatory=True),

                'x-content-type-options':
                    HeaderDefinition(pattern=r'^(?=.*nosniff).*$', obligatory=True),

                'x-download-options':
                    HeaderDefinition(pattern=r'^(?=.*noopen).*$', obligatory=True),

                'x-permitted-cross-domain-policies':
                    HeaderDefinition(pattern=r'^none$', obligatory=True),

                'x-xss-protection':
                    HeaderDefinition(pattern=r'^1$', obligatory=True)
            }
        },
        'whatweb': {
            'class': WhatWebTool
        },
        'testssl': {
            'class': SSLTool,
        },
        'cve-search': {
            'class': CVESearchTool,
        },
        'aucote-active-directory': {
            'class': AucoteActiveDirectory
        }
    },
    'node_scan': ['cve-search']
}
