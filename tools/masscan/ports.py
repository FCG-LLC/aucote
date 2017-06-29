"""
Provides class for scanning ports

"""
from tools.common.scan_task import ScanTask
from tools.masscan.base import MasscanBase
from aucote_cfg import cfg
from tools.nmap.tool import NmapTool
from utils.config import Config
from utils.exceptions import StopCommandException


class MasscanPorts(ScanTask):
    """
    Scans for open ports using masscan application

    """

    def __init__(self, tcp=True, udp=True):
        self.tcp = tcp
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
        args = ['--rate', str(cfg['portdetection.tcp.scan_rate'] if self.tcp else cfg['portdetection.udp.scan_rate'])]

        include_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.tcp.ports.include'],
                                                      udp=self.udp and cfg['portdetection.udp.ports.include'])

        exclude_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.tcp.ports.exclude'],
                                                      udp=self.udp and cfg['portdetection.udp.ports.exclude'])

        if not include_ports:
            raise StopCommandException("No ports for scan")
        args.extend(['--ports', include_ports])

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend([str(node.ip) for node in nodes])

        return args
