from aucote_cfg import cfg
from xml.etree import ElementTree
import logging as log
from scans.structs import Port, TransportProtocol
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
    def __init__(self, port):
        self.port = port

    def run(self):
        args = self.COMMON_ARGS + ( '-p', str(self.port.number), '-sV', '--script', self.NAME, str(self.port.node.ip))
        xml = self.call_nmap(args)
        host = xml.find('host')
        if host is not None:
            ports = host.find('ports')
            if ports is not None:
                port = ports.find('port')
                if port is not None:
                    for script in port.findall('script'):
                        if script.get('id') == self.NAME:
                            log.debug('Parsing output from script %s', self.NAME)
                            try:
                                return self.handle_script(script)
                            except Exception as err:
                                log.warning('Exception while parsing output from script %s', self.NAME, exc_info=err)
                                log.debug('Problematic XML: %s', ElementTree.dump(script))
        log.debug('Did not found output of script %s', self.NAME)
        return None

    def handle_script(self, script):
        raise NotImplementedError


