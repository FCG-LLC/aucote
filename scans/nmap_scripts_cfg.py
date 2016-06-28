from tools.nmap.scripts import *

SERVICE_TO_SCRIPTS = {
    'ftp': [FtpVsftpdBackdoor, FtpAnon],
    'netbios-ssn': [SmbVulnCve2009_3103, SmbOsDiscovery],
    'http': [HttpSlowLorisCheck, HtttpVulnCve2015_1635, HtttpVulnCve2014_2127, HtttpVulnCve2014_2129, HtttpVulnCve2014_2126, HtttpVulnCve2015_1427, HttpEnum, HttpPhpVersion],
    'https': [SslHeartbleed, SslDhParams, SslPoodle, SslCcsInjection, HtttpVulnCve2015_1635, HtttpVulnCve2014_2127, HtttpVulnCve2014_2129, HtttpVulnCve2014_2126, HtttpVulnCve2015_1427, HttpEnum, HttpPhpVersion],
    'distccd': [DistccCve2004_2687],
    'rmiregistry': [RmiVulnClassLoader],
    'mysql': [MySqlInfo],
    'irc': [IrcUnrealircdBackdoor],
    'iscsi': [IscsiInfo],
    'ssh': [Ssh2EnumAlgos, SshHostKey],
    'isakmp': [IkeVersion],
    'ldap': [LdapSearch],
    'vnc': [VncInfo],
    'rpcbind': RpcInfo
}

PORT_TO_SCRIPTS = {
    27017: [MongodbDatabases, MongodbInfo],
    
}