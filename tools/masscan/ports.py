"""
Provides class for scanning ports

"""
from tools.common.scan_task import ScanTask
from tools.masscan.base import MasscanBase
from aucote_cfg import cfg
from tools.nmap.tool import NmapTool
from utils.config import Config


class MasscanPorts(ScanTask):
    """
    Scans for open ports using masscan application

    """

    def __init__(self, udp=True):
        self.udp = udp
        super(MasscanPorts, self).__init__(MasscanBase())

    def prepare_args(self, nodes):
        """
        Prepare args for command execution

        Args:
            nodes (list): nodes from scanning

        Returns:
            list

        """
        args = ['--rate', str(cfg['portdetection.network_scan_rate'])]

        if not self.udp:
            args.extend(['--exclude-ports', 'U:0-65535'])

        include_ports = NmapTool.list_to_ports_string(tcp=cfg['portdetection.ports.tcp.include'],
                                                      udp=cfg['portdetection.ports.udp.include'])

        exclude_ports = NmapTool.list_to_ports_string(tcp=cfg['portdetection.ports.tcp.exclude'],
                                                      udp=cfg['portdetection.ports.udp.exclude'])

        if include_ports:
            args.extend(['--ports', include_ports])

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend([str(node.ip) for node in nodes])

        return args
