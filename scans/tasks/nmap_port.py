import logging as log
from database.serializer import Serializer
from tools.nmap.base import NmapBase


class NmapPortScanTask(NmapBase):
    """
    Scans one port using provided vulnerability scan
    """

    def __init__(self, executor, port, script_classes):
        """
        Initialize variables
        Args:
            executor:
            port:
            script_clases:
        """
        super().__init__(executor=executor)
        self._port = port
        self._script_classes = script_classes

    @property
    def port(self):
        """
        Returns port
        """
        return self._port

    @property
    def script_classes(self):
        """
        Returns script classes
        """
        return self._script_classes

    def __call__(self):
        """
        Implement Tasks call method:
        scans port used nmap and provided script classes
        send serialized vulnerabilities to kudu queue
        """
        vulners = []
        if self._script_classes:
            scripts = {script.name: script for script in self._script_classes}
            args = ['-p', str(self._port.number), '-sV']
            if self._port.transport_protocol.name == "UDP":
                args.append("-sU")
            for script in scripts.values():
                args.append('--script')
                args.append(script.name)
                if script.args is not None:
                    args.append('--script-args')
                    args.append(script.args)
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
