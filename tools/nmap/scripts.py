from .base import NmapScript 

#SSL================================
class SslCcsInjection(NmapScript):
    NAME = 'ssl-ccs-injection'

class SslDhParams(NmapScript):
    NAME = 'ssl-dh-params'

class SslHeartbleed(NmapScript):
    NAME = 'ssl-heartbleed'

class SslPoodle(NmapScript):
    NAME = 'ssl-poodle'

#SSH=================================
class Ssh2EnumAlgos(NmapScript):
    NAME='ssh2-enum-algos'

class SshHostKey(NmapScript):
    NAME = 'ssh-hostkey'

#SAMBA===============================
class SmbCheckVulns(NmapScript):
    NAME = 'smb-check-vulns'

class SmbVulnCve2009_3103(NmapScript):
    NAME = 'smb-vuln-cve2009-3103'

#HTTP=================================
class HttpSlowLorisCheck(NmapScript):
    NAME='http-slowloris-check'
    ARGS='http-slowloris.threads=500,http-slowloris.timeout=200'

class HtttpVulnCve2014_2129(NmapScript):
    NAME = 'http-vuln-cve2014-2129'

class HtttpVulnCve2014_2127(NmapScript):
    NAME = 'http-vuln-cve2014-2127'

class HtttpVulnCve2014_2126(NmapScript):
    NAME = 'http-vuln-cve2014-2126'

class HtttpVulnCve2015_1635(NmapScript):
    NAME = 'http-vuln-cve2015-1635'

class HtttpVulnCve2015_1427(NmapScript):
    NAME = 'http-vuln-cve2015-1427'

class HttpPhpVersion(NmapScript):
    NAME = 'http-php-version'

class FtpVsftpdBackdoor(NmapScript):
    NAME = 'ftp-vsftpd-backdoor'

class FtpAnon(NmapScript):
    NAME = 'ftp-anon'

class DistccCve2004_2687(NmapScript):
    NAME = 'distcc-cve2004-2687'

class MySqlInfo(NmapScript):
    NAME = 'mysql-info'

class RmiVulnClassLoader(NmapScript):
    NAME = 'rmi-vuln-classloader'

class IscsiInfo(NmapScript):
    NAME = 'iscsi-info'
