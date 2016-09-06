from structs import Vulnerability
from tools.common.command import CommandXML


class NmapBase(CommandXML):
    '''
    Base for all classes using nmap application.
    '''
    COMMON_ARGS = ('-n', '--privileged', '-oX', '-', '-T4')
    NAME = 'nmap'


class NmapScript(object):
    def __init__(self, port, exploit, name=None, args=None):
        self.exploit = exploit
        self.port = port
        self.name = name
        self.args = args

    def get_result(self, script):
        raise NotImplementedError


class VulnNmapScript(NmapScript):
    @classmethod
    def get_result(cls, script):
        table = script.find('table')
        if table is None: return None #no data, probably no response from server, so no problem detected
        state = table.find("./elem[@key='state']").text
        if state not in ('VULNERABLE', 'LIKELY VULNERABLE'): return None #TODO: add likelihood to vulnerability
        return script.get('output').strip()


class InfoNmapScript(NmapScript):
    @classmethod
    def get_result(cls, script):
        return ''


