"""
Provides class for scanning ports

"""
import logging as log
from tools.common import OpenPortsParser
from tools.masscan.base import MasscanBase
from utils.exceptions import NonXMLOutputException
from aucote_cfg import cfg


class MasscanPorts(MasscanBase):
    """
    Scans for open ports using masscan application

    """

    def scan_ports(self, nodes):
        """
        Scan for ports

        Args:
            nodes (list):

        Returns:
            list

        """
        if not nodes:
            return []

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
        args = ['--rate', str(cfg.get('service.scans.rate')),
                '--ports', str(cfg.get('service.scans.ports'))]
        args.extend(cfg.get('tools.masscan.args').cfg)

        args.extend([str(node.ip) for node in nodes])

        return args
