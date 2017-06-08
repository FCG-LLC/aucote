"""
Provides task responsible for obtain detailed information about port
"""
import logging as log

from aucote_cfg import cfg
from database.serializer import Serializer
from structs import BroadcastPort, TransportProtocol
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

        self.kudu_queue.send_msg(Serializer.serialize_port_vuln(self._port, None), dont_wait=True)

        if not self.scan_only:
            await self.aucote.task_mapper.assign_tasks(self._port, self.aucote.storage)
