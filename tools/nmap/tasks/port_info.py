"""
Provides task responsible for obtain detailed information about port
"""
import logging as log

from database.serializer import Serializer
from tools.nmap.base import NmapBase
from utils.task import Task


class NmapPortInfoTask(Task):
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
        self.command = NmapBase()

    def prepare_args(self):
        """
        Prepares args for command call

        Returns:
            list

        """
        args = list()
        args.extend(('-p', str(self._port.number), '-sV'))
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
        if self._port.is_broadcast or self._port.is_physical:
            self.executor.task_mapper.assign_tasks(self._port, self.executor.storage)
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
            self._port.service_version = service.get('version')

        self.kudu_queue.send_msg(Serializer.serialize_port_vuln(self._port, None))

        self.executor.task_mapper.assign_tasks(self._port, self.executor.storage)
