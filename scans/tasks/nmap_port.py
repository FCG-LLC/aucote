from .base import ScanTask
from tools.nmap import NmapBase
import logging as log

class NmapPortScanTask(NmapBase):
    '''
    Scans one port using provided vulnerability scan
    '''

    def __init__(self, port, script_clases):
        self._port = port
        self._script_classes = script_clases

    def __call__(self):
        scripts = {cls.NAME:cls(self._port, self.exploits.find('nmap', cls.NAME)) for cls in self._script_classes}
        args = list(self.COMMON_ARGS)
        args.extend(( '-p', str(self._port.number), '-sV'))
        for script in scripts.values():
            args.append('--script')
            args.append(script.NAME)
            if script.ARGS is not None:
                args.append('--script-args')
                args.append(script.ARGS)
        args.append(str(self._port.node.ip))
        xml = self.call_nmap(args)
        host = xml.find('host')
        if host is not None:
            ports = host.find('ports')
            if ports is not None:
                port = ports.find('port')
                if port is not None:
                    for script in port.findall('script'):
                        found_handler = scripts.get(script.get('id'))
                        if found_handler is None: continue
                        log.debug('Parsing output from script %s', script.get('id'))
                        vuln = found_handler.handle(script)
                        if vuln is not None:
                            self.db.insert_vulnerability(vuln)




