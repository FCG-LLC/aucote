"""
This module contains class responsible for scanning ports by using nmap

"""
from tools.common import OpenPortsParser
from .base import NmapBase


class PortsScan(NmapBase):
    """
    This class is responsible for scanning node

    """

    def scan_ports(self, nodes, ports=None):
        """
        Scan nodes for open ports. If ports are passed, scans only them. Returns list of open ports.

        Args:
            nodes (list):
            ports (list):

        Returns:
            list

        """
        node_by_ip = {node.ip: node for node in nodes}
        args = list(self.COMMON_ARGS)
        if ports is None:
            args.extend(('-p', '0-65535'))
        else:
            port_str = ','.join([str(port) for port in ports])
            args.extend(('-p', port_str))
        args.extend(('-sV', '--script', 'banner'))
        args.extend([str(node.ip) for node in nodes])
        xml = self.call(args)

        return OpenPortsParser.parse(xml=xml, node_by_ip=node_by_ip)
