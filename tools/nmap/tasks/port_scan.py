"""
Contains class responsible for exploiting port by using nmap scripts

"""
import logging as log

from aucote_cfg import cfg
from structs import Vulnerability, PhysicalPort, BroadcastPort
from tools.common.command_task import CommandTask
from tools.nmap.base import NmapBase


class NmapPortScanTask(CommandTask):
    """
    Scans one port using provided vulnerability scan

    """

    def __init__(self, script_classes, rate, *args, **kwargs):
        """
        Init variables

        Args:
            port (Port):
            script_classes (list):
            *args:
            **kwargs:
        """

        self._script_classes = script_classes
        exploits = [script.exploit for script in self._script_classes]
        super().__init__(command=NmapBase(), exploits=exploits, *args, **kwargs)
        self.scripts = {script.name: script for script in self._script_classes}
        self.rate = rate

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
        """
        Prepares arguments for command execution

        Returns:
            list

        """
        args = [
            '--max-rate', str(self.rate),
            '-sS',
            '-sU'
        ]

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        scripts = self.scripts.values()

        script_names = ",".join([script.name for script in scripts if script.name])
        script_args = ",".join({script.args for script in scripts if script.args})

        args.extend(["--script", script_names])

        if script_args:
            args.extend(["--script-args", script_args])

        if isinstance(self._port, (PhysicalPort, BroadcastPort)):
            if isinstance(self._port, PhysicalPort):
                args.append('-e')
                args.append(self._port.interface)

            return args

        args.extend(('-p', str(self._port.number), '-sV'))

        if self._port.is_ipv6:
            args.append("-6")

        if self._port.number == 53:
            args.extend(["--dns-servers", str(self._port.node.ip)])

        args.append(str(self._port.node.ip))

        return args

    def _get_vulnerabilities(self, results):
        """
        Proceed results of command execution and returns list of vulnerabilities

        Args:
            results:

        Returns:
            list

        """
        tmp_scripts = results.findall('host/ports/port/script') or []
        tmp_scripts.extend(results.findall('prescript/script') or [])
        tmp_scripts.extend(results.findall('host/hostscript/script') or [])

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
