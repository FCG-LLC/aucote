"""
Provides class for scanning ports

"""
from tools.common.port_scan_task import PortScanTask
from tools.masscan.base import MasscanBase
from aucote_cfg import cfg
from tools.nmap.tool import NmapTool
from utils.exceptions import StopCommandException


class MasscanPorts(PortScanTask):
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
        args = list(cfg['tools.masscan.args'])
        args.extend(['--rate', str(cfg['portdetection.network_scan_rate'])])

        include_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.ports.tcp.include'],
                                                      udp=self.udp and cfg['portdetection.ports.udp.include'])

        exclude_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.ports.tcp.exclude'],
                                                      udp=self.udp and cfg['portdetection.ports.udp.exclude'])

        if not include_ports:
            raise StopCommandException("No ports for scan")
        args.extend(['--ports', include_ports])

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend([str(node.ip) for node in nodes])

        return args
