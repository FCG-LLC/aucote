"""
Base class for scanners

"""
import logging as log

from tornado import gen

from tools.common import OpenPortsParser
from utils.exceptions import NonXMLOutputException, StopCommandException


class PortScanTask(object):
    """
    Base class for scanner

    """

    def __init__(self, command):
        self.command = command

    async def prepare_args(self, nodes):
        """
        Prepare args for command execution

        Args:
            nodes (list): nodes from scanning

        Returns:
            list

        """
        raise NotImplementedError

    async def scan_ports(self, nodes):
        """
        Scan nodes for open ports. If ports are passed, scans only them. Returns list of open ports.

        Args:
            nodes (list):
            ports (list):

        Returns:
            list

        """
        if not nodes:
            return []

        try:
            args = await self.prepare_args(nodes)
        except StopCommandException as exception:
            log.warning("Cannot execute command: %s", str(exception))
            return []

        try:
            xml = await self.command.async_call(args, timeout=0)
        except NonXMLOutputException:
            return []
        except gen.TimeoutError:
            return []

        node_by_ip = {node.ip: node for node in nodes}
        ports = OpenPortsParser.parse(xml, node_by_ip)
        return ports

    def cancel(self):
        if self.command:
            self.command.kill()
