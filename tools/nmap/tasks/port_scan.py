"""
Contains class responsible for exploiting port by using nmap scripts

"""
import logging as log
import subprocess
import time

from structs import Vulnerability, Port, Scan
from tools.nmap.base import NmapBase
from utils.task import Task


class NmapPortScanTask(Task):
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

        self._script_classes = script_classes
        self.current_exploits = [script.exploit for script in self._script_classes]
        super().__init__(*args, **kwargs)
        self._port = port
        self.scripts = {script.name: script for script in self._script_classes}
        self.command = NmapBase()

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

    def prepare_args(self):
        if self._port == Port.broadcast():
            args = []
            for script in self.scripts.values():
                args.append('--script')
                args.append(script.name)
            return args

        args = ['-p', str(self._port.number), '-sV']
        if self._port.transport_protocol.name == "UDP":
            args.append("-sU")

        if self._port.number == 53:
            args.extend(["--dns-servers", str(self._port.node.ip)])

        for script in self.scripts.values():
            args.append('--script')
            args.append(script.name)
            if script.args is not None:
                args.append('--script-args')
                args.append(script.args)

        args.append(str(self._port.node.ip))

        return args

    def __call__(self):
        """
        Implement Tasks call method:
        scans port used nmap and provided script classes
        send serialized vulnerabilities to kudu queue

        """

        args = self.prepare_args()

        try:
            results = self.command.call(args=args)
        except subprocess.CalledProcessError as exception:
            self._port.scan = Scan(0, 0)
            self.executor.storage.save_scans(exploit=self.current_exploits, port=self._port)
            log.warning("Exiting process %s ", self.command.NAME, exc_info=exception)
            return None

        self._port.scan.end = time.time()
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

        if not results:
            log.debug("Process %s does not return any result.", self.command.NAME)
            return None

        vulnerabilities = self.get_vulnerabilities(results)

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                self.store_vulnerability(vulnerability)

        return results

    def get_vulnerabilities(self, results):
        tmp_scripts = results.findall('host/ports/port/script') or []
        tmp_scripts.extend(results.findall('prescript/script') or [])

        vulnerabilities = []
        for script in tmp_scripts:
            found_handler = self.scripts.get(script.get('id'))
            if found_handler is None:
                continue
            log.debug('Parsing output from script %s', script.get('id'))

            result = found_handler.get_result(script)
            if result is None:
                continue

            vulnerabilities.append(Vulnerability(exploit=found_handler.exploit, port=self._port, output=result))

        return vulnerabilities

