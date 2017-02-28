"""
Provides task responsible for obtain detailed information about port
"""
import logging as log

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import BroadcastPort
from structs import PhysicalPort
from tools.common.port_task import PortTask
from tools.nmap.base import NmapBase


class NmapPortInfoTask(PortTask):
    """
    Scans one port using provided vulnerability scan

    """

    def __init__(self, scan_only=False, *args, **kwargs):
        """
        Initiazlize variables.

        Args:
            port (Port):
            *args:
            **kwargs:

        """
        super().__init__(exploits=[], *args, **kwargs)
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
            '-sV',
            '--max-rate', str(cfg.get('service.scans.port_scan_rate'))
        ]

        if self._port.transport_protocol.name == "UDP":
            args.append("-sU")

        if self._port.is_ipv6:
            args.append("-6")

        args.extend(('--script', 'banner'))
        args.append(str(self._port.node.ip))

        return args

    def __call__(self):
        """
        Scans port, parses output for obtain information about service name and version and pass it to the task mapper

        Returns:
            None

        """
        if isinstance(self._port, (BroadcastPort, PhysicalPort)):
            self.aucote.task_mapper.assign_tasks(self._port, self.aucote.storage)
            return

        args = self.prepare_args()

        xml = self.command.call(args=args)
        banner = xml.find("host/ports/port/script[@id='banner']")
        if banner is None:
            log.warning('No banner for %s:%i', self._port.node.ip, self._port.number)
        else:
            self._port.banner = banner.get('output')
        service = xml.find("host/ports/port/service")
        if service is None:
            log.warning('No service for %s:%i', self._port.node.ip, self._port.number)
        else:
            self._port.service_name = service.get('name')
            if self._port.service_name == 'http':
                if service.get('tunnel') == 'ssl':
                    self._port.service_name = 'https'

            self._port.service_version = "{0} {1}".format(service.get('product') or "",
                                                          service.get('version') or "").strip()

        self.kudu_queue.send_msg(Serializer.serialize_port_vuln(self._port, None))

        if not self.scan_only:
            self.aucote.task_mapper.assign_tasks(self._port, self.aucote.storage)
