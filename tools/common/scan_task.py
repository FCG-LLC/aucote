"""
Base class for scanners

"""
from tools.common import OpenPortsParser
from utils.exceptions import NonXMLOutputException


class ScanTask(object):
    """
    Base class for scanner

    """

    def __init__(self, command):
        self.command = command

    def prepare_args(self, nodes):
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

        args = self.prepare_args(nodes)

        try:
            xml = await self.command.async_call(args)
        except NonXMLOutputException:
            return []

        node_by_ip = {node.ip: node for node in nodes}
        ports = OpenPortsParser.parse(xml, node_by_ip)
        return ports
