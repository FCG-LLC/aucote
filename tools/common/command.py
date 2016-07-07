from xml.etree import ElementTree
import logging as log
from aucote_cfg import cfg
import subprocess

class Command:
    '''
    Base file for all classes that call a command (create process) using command line arguments.
    '''

    #to be set by child classes.
    COMMON_ARGS = None
    NAME = None

    def call(self, args):
        all_args = nmap_args = [cfg.get('tools.%s.cmd'%self.NAME)]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        log.debug('Executing: %s', ' '.join(all_args))
        xml_txt = subprocess.check_output(all_args, stderr=subprocess.DEVNULL)
        return ElementTree.fromstring(xml_txt)
