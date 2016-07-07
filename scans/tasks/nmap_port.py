from .base import ScanTask
from tools.nmap import NmapBase
import logging as log
from database.serializer import Serializer

class NmapPortScanTask(NmapBase):
    '''
    Scans one port using provided vulnerability scan
    '''

    def __init__(self, port, script_clases):
        self._port = port
        self._script_classes = script_clases

    def __call__(self):
        vulners = []
        if self._script_classes:
            scripts = {cls.NAME:cls(self._port, self.exploits.find('nmap', cls.NAME)) for cls in self._script_classes}
            #args = list(self.COMMON_ARGS)
            args = ['-p', str(self._port.number), '-sV']
            for script in scripts.values():
                args.append('--script')
                args.append(script.NAME)
                if script.ARGS is not None:
                    args.append('--script-args')
                    args.append(script.ARGS)
            args.append(str(self._port.node.ip))
            xml = self.call(args)
            for script in xml.findall('host/ports/port/script'):
                found_handler = scripts.get(script.get('id'))
                if found_handler is None: continue
                log.debug('Parsing output from script %s', script.get('id'))
                vuln = found_handler.handle(script)
                if vuln is not None:
                    vulners.append(vuln)
        serializer = Serializer()
        if vulners:
            for vuln in vulners:
                log.debug('Found vulnerability: port=%s exploit=%s output=%s', vuln.port, vuln.exploit.id, vuln.output)
                msg = serializer.serialize_port_vuln(vuln.port, vuln)
                self.kudu_queue.send_msg(msg)
        else:
            msg = serializer.serialize_port_vuln(self._port, None)
            self.kudu_queue.send_msg(msg)





