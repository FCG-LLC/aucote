from aucote_cfg import cfg
from xml.etree import ElementTree
import logging as log
from structs import Port, TransportProtocol, Vulnerability
import subprocess


class NmapBase:
    '''
    Base for all classes using nmap application.
    '''
    COMMON_ARGS = ('-n', '--privileged', '-oX', '-', '-T4')
    def call_nmap(self, args):
        nmap_args = [cfg.get('tools.nmap.cmd')]
        nmap_args.extend(args)
        log.debug('Executing: %s', ' '.join(nmap_args))
        xml_txt = subprocess.check_output(nmap_args, stderr=subprocess.DEVNULL)
        return ElementTree.fromstring(xml_txt)

class NmapScript(NmapBase):
    NAME = None
    ARGS = None

    def __init__(self, port, exploit):
        self.exploit = exploit
        self.port = port

    def handle(self, script):
        table = script.find('table')
        if table is None: return #no data, probably no response from server, so no problem
        state = table.find("./elem[@key='state']").text
        if state  not in ('VULNERABLE', 'LIKELY VULNERABLE'): return None #TODO: add likelihood to vulnerability
        result = Vulnerability()
        result.exploit = self.exploit
        result.port = self.port
        result.output = script.get('output')
        return result


