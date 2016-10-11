"""
Contains class responsible for exploiting port by using nmap scripts

"""
import logging as log
import time

from database.serializer import Serializer
from structs import Vulnerability
from tools.nmap.base import NmapBase


class NmapPortScanTask(NmapBase):
    """
    Scans one port using provided vulnerability scan

    """

    def __init__(self, port, script_classes, *args, **kwargs):
        """
        Init variables

        Args:
            port (Port):
            script_classes (list):
            *args:
            **kwargs:
        """

        super().__init__(*args, **kwargs)
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
        scripts = {script.name: script for script in self._script_classes}
        args = ['-p', str(self._port.number), '-sV']
        if self._port.transport_protocol.name == "UDP":
            args.append("-sU")

        if self._port.number == 53:
            args.extend(["--dns-servers", str(self._port.node.ip)])

        for script in scripts.values():
            args.append('--script')
            args.append(script.name)
            if script.args is not None:
                args.append('--script-args')
                args.append(script.args)
        args.append(str(self._port.node.ip))

        xml = self.call(args=args)

        tmp_scripts = xml.findall('host/ports/port/script') or []
        tmp_scripts.extend(xml.findall('prescript/script') or [])

        for script in tmp_scripts:
            found_handler = scripts.get(script.get('id'))
            if found_handler is None:
                continue
            log.debug('Parsing output from script %s', script.get('id'))

            result = found_handler.get_result(script)
            if result is None:
                continue

            vulners.append(Vulnerability(exploit=found_handler.exploit, port=self._port, output=result))

        exploits = [script.exploit for script in self._script_classes]

        self._port.scan.end = time.time()
        self.store_scan_end(exploits=exploits, port=self._port)

        if vulners:
            for vuln in vulners:
                self.store_vulnerability(vuln)
        else:
            msg = Serializer.serialize_port_vuln(self._port, None)
            self.kudu_queue.send_msg(msg)
