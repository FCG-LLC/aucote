from .base import VulnNmapScript, InfoNmapScript

#SSL================================
class SslCcsInjection(VulnNmapScript):
    NAME = 'ssl-ccs-injection'

class SslDhParams(VulnNmapScript):
    NAME = 'ssl-dh-params'

class SslHeartbleed(VulnNmapScript):
    NAME = 'ssl-heartbleed'

class SslPoodle(VulnNmapScript):
    NAME = 'ssl-poodle'

#SAMBA===============================

class SmbVulnCve2009_3103(VulnNmapScript):
    NAME = 'smb-vuln-cve2009-3103'

#HTTP=================================
class HttpSlowLorisCheck(VulnNmapScript):
    NAME='http-slowloris-check'
    ARGS='http-slowloris.threads=500,http-slowloris.timeout=200'

class HtttpVulnCve2014_2129(VulnNmapScript):
    NAME = 'http-vuln-cve2014-2129'

class HtttpVulnCve2014_2127(VulnNmapScript):
    NAME = 'http-vuln-cve2014-2127'

class HtttpVulnCve2014_2126(VulnNmapScript):
    NAME = 'http-vuln-cve2014-2126'

class HtttpVulnCve2015_1635(VulnNmapScript):
    NAME = 'http-vuln-cve2015-1635'

class HtttpVulnCve2015_1427(VulnNmapScript):
    NAME = 'http-vuln-cve2015-1427'

class FtpVsftpdBackdoor(VulnNmapScript):
    NAME = 'ftp-vsftpd-backdoor'

class FtpAnon(VulnNmapScript):
    NAME = 'ftp-anon'

class DistccCve2004_2687(VulnNmapScript):
    NAME = 'distcc-cve2004-2687'

class RmiVulnClassLoader(VulnNmapScript):
    NAME = 'rmi-vuln-classloader'


class IrcUnrealircdBackdoor(VulnNmapScript):
    NAME = 'irc-unrealircd-backdoor'


#INFO =================================================
class IscsiInfo(InfoNmapScript):
    NAME = 'iscsi-info'

class Ssh2EnumAlgos(InfoNmapScript):
    NAME='ssh2-enum-algos'

class SshHostKey(InfoNmapScript):
    NAME = 'ssh-hostkey'

class SmbOsDiscovery(InfoNmapScript):
    NAME = 'smb-os-discovery'

class MySqlInfo(InfoNmapScript):
    NAME = 'mysql-info'

class MongodbDatabases(InfoNmapScript):
    NAME = 'mongodb-databases'

class MongodbInfo(InfoNmapScript):
    NAME = 'mongodb-info'

class IkeVersion(InfoNmapScript):
    NAME = 'ike-version'

class LdapSearch(InfoNmapScript):
    NAME = 'ldap-search'

class HttpEnum(InfoNmapScript):
    NAME = 'http-enum'

class HttpPhpVersion(InfoNmapScript):
    NAME = 'http-php-version'

class VncInfo(InfoNmapScript):
    NAME = 'vnc-info'

class RpcInfo(InfoNmapScript):
    NAME = 'rpcinfo'






