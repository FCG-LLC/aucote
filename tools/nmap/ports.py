"""
This module contains class responsible for scanning ports by using nmap

"""
import logging as log
from tools.common import OpenPortsParser
from utils.exceptions import NonXMLOutputException
from .base import NmapBase
from aucote_cfg import cfg


class PortsScan(NmapBase):
    """
    This class is responsible for scanning node

    """

    def scan_ports(self, nodes):
        """
        Scan nodes for open ports. If ports are passed, scans only them. Returns list of open ports.

        Args:
            nodes (list):
            ports (list):

        Returns:
            list

        """
        log.info("Scanning ports")

        args = self.prepare_args(nodes)

        try:
            xml = self.call(args)
        except NonXMLOutputException:
            return []

        parser = OpenPortsParser()
        node_by_ip = {node.ip: node for node in nodes}
        ports = parser.parse(xml, node_by_ip)
        return ports

    @classmethod
    def prepare_args(cls, nodes):
        """
        Prepare args for command execution

        Args:
            nodes (list): nodes from scanning

        Returns:
            list

        """
        args = ['-sV', '--script', 'banner']
        args.extend(['-p', str(cfg.get('service.scans.ports'))])

        args.extend([str(node.ip) for node in nodes])
        return args
