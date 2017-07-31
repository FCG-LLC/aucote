"""
Provides task responsible for obtain detailed information about port
"""
import logging as log

import time

from aucote_cfg import cfg
from database.serializer import Serializer
from fixtures.exploits import Exploit
from scans.task_mapper import TaskMapper
from structs import BroadcastPort, TransportProtocol, Vulnerability, Scan, VulnerabilityChange
from structs import PhysicalPort
from tools.common.port_task import PortTask
from tools.nmap.base import NmapBase


class NmapPortInfoTask(PortTask):
    """
    Scans one port using provided vulnerability scan

    """
    SERVICE_PROTOCOL = 1
    SERVICE_NAME = 2
    SERVICE_VERSION = 3
    SERVICE_BANNER = 4
    SERVICE_CPE = 5

    def __init__(self, scan_only=False, *args, **kwargs):
        """
        Initiazlize variables.

        Args:
            port (Port):
            *args:
            **kwargs:

        """
        super().__init__(exploits=[Exploit(exploit_id=0, name='portscan', app='portscan')], *args, **kwargs)

        self.command = NmapBase()
        self.scan_only = scan_only

    def prepare_args(self):
        """
        Prepares args for command call

        Returns:
            list

        """
        args = [
            '-p', str(self._port.number),
            '-sV', '-Pn',
            '--version-all',
            '--max-rate', str(cfg['portdetection.port_scan_rate'])
        ]

        if self._port.transport_protocol == TransportProtocol.TCP:
            args.append('-sS')

        elif self._port.transport_protocol == TransportProtocol.UDP:
            args.append('-sU')

        if self._port.is_ipv6:
            args.append("-6")

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        args.extend(('--script', 'banner'))
        args.append(str(self._port.node.ip))

        return args

    async def __call__(self):
        """
        Scans port, parses output for obtain information about service name and version and pass it to the task mapper

        Returns:
            None

        """
        if isinstance(self._port, (BroadcastPort, PhysicalPort)):
            await self.aucote.task_mapper.assign_tasks(self._port, self.aucote.storage)
            return

        args = self.prepare_args()

        xml = await self.command.async_call(args=args)
        banner = xml.find("host/ports/port/script[@id='banner']")
        if banner is None:
            log.warning('No banner for %s:%i', self._port.node.ip, self._port.number)
        else:
            self._port.banner = banner.get('output')
        service = xml.find("host/ports/port/service")
        if service is None:
            log.warning('No service for %s:%i', self._port.node.ip, self._port.number)
        else:
            self._port.protocol = service.get('name')
            if self._port.protocol == 'http':
                if service.get('tunnel') == 'ssl':
                    self._port.protocol = 'https'

            self._port.service.name = service.get('product')
            self._port.service.version = service.get('version')

            cpe = service.find("cpe")
            if cpe is not None:
                self._port.service.cpe = cpe.text

        self.storage.save_security_scan(port=self.port, exploit=self.exploit, scan=self._scan)
        cpe = self.port.service.cpe.as_fs() if self.port.service.cpe else None

        vulnerabilities = [
            Vulnerability(exploit=self.exploit, port=self.port, output=self.port.protocol, subid=self.SERVICE_PROTOCOL),
            Vulnerability(exploit=self.exploit, port=self.port, output=self.port.service.name, subid=self.SERVICE_NAME),
            Vulnerability(exploit=self.exploit, port=self.port, output=self.port.service.version,
                          subid=self.SERVICE_VERSION),
            Vulnerability(exploit=self.exploit, port=self.port, output=self.port.banner, subid=self.SERVICE_BANNER),
            Vulnerability(exploit=self.exploit, port=self.port, output=cpe, subid=self.SERVICE_CPE)
        ]
        self.aucote.storage.save_vulnerabilities(vulnerabilities=vulnerabilities, scan=self._scan)

        self.kudu_queue.send_msg(Serializer.serialize_port_vuln(self._port, None), dont_wait=True)
        self.diff_with_last_scan()

        if not self.scan_only:
            await TaskMapper(aucote=self.aucote, scan=self._scan).assign_tasks(self._port, self.aucote.storage)

    def diff_with_last_scan(self):
        """
        Differentiate two last scans.

        Obtain exploits scanned in current scan.
        For each exploit check what changed in findings from last scan of this exploits

        Args:

        Returns:
            None

        """
        changes = []

        for exploit in self.current_exploits:
            last_scans = self.storage.get_scans_by_security_scan(port=self.port, exploit=exploit)
            _current_findings = self.storage.get_vulnerabilities(port=self.port, exploit=exploit, scan=self._scan)

            if len(last_scans) < 2:
                _previous_findings = []
            else:
                _previous_findings = self.storage.get_vulnerabilities(port=self.port, exploit=exploit,
                                                                      scan=last_scans[1])

            common_findings = []

            for current_finding in _current_findings:
                for previous_finding in _previous_findings:
                    if current_finding == previous_finding:
                        break

                    if current_finding.is_almost_equal(previous_finding):
                        common_findings.append(
                            {
                                'prev': previous_finding,
                                'curr': current_finding
                            })
                        break

            current_findings = list(set(_current_findings) - set(_previous_findings) -
                                    set(finding['curr'] for finding in common_findings))
            previous_findings = list(set(_previous_findings) - set(_current_findings) -
                                     set(finding['prev'] for finding in common_findings))

            changes.extend(VulnerabilityChange(change_time=time.time(), previous_finding=None,
                                               current_finding=vuln) for vuln in current_findings)

            changes.extend(VulnerabilityChange(current_finding=None, change_time=time.time(),
                                               previous_finding=vuln) for vuln in previous_findings)

            changes.extend(VulnerabilityChange(current_finding=vuln['curr'], change_time=time.time(),
                                               previous_finding=vuln['prev']) for vuln in common_findings)

        self.storage.save_changes(changes)
        for change in changes:
            self.aucote.kudu_queue.send(Serializer.serialize_vulnerability_change(change))
