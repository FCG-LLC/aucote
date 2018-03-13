"""
Provides class for scanning ports

"""
from tools.common.port_scan_task import PortScanTask
from tools.masscan.base import MasscanBase
from tools.nmap.tool import NmapTool
from aucote_cfg import cfg
from utils.exceptions import StopCommandException


class MasscanPorts(PortScanTask):
    """
    Scans for open ports using masscan application

    """

    def __init__(self, tcp=True, udp=True):
        super(MasscanPorts, self).__init__(MasscanBase(), tcp=tcp, udp=udp)

    async def prepare_args(self, nodes):
        """
        Prepare args for command execution

        Args:
            nodes (list): nodes from scanning

        Returns:
            list

        """
        args = list(cfg['tools.masscan.args'])

        rate = self.scan_rate()

        args.extend(['--rate', rate])

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
