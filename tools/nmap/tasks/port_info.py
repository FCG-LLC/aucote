"""
Provides task responsible for obtain detailed information about port
"""
import logging as log

from tools.nmap.base import NmapBase
from utils.task import Task


class NmapPortInfoTask(Task, NmapBase):
    """
    Scans one port using provided vulnerability scan

    """

    def __init__(self, port, *args, **kwargs):
        """
        Initiazlize variables.

        Args:
            port (Port):
            *args:
            **kwargs:

        """
        super().__init__(*args, **kwargs)
        self._port = port

    def __call__(self):
        """
        Scans port, parses output for obtain information about service name and version and pass it to the task mapper

        Returns:
            None

        """
        args = list()
        args.extend(('-p', str(self._port.number), '-sV'))
        if self._port.transport_protocol.name == "UDP":
            args.append("-sU")
        args.extend(('--script', 'banner'))
        args.append(str(self._port.node.ip))
        xml = self.call(args=args)
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
            self._port.service_version = service.get('version')

        self.executor.task_mapper.assign_tasks(self._port, self.executor.storage)
