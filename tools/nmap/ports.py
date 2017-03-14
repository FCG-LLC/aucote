"""
This module contains class responsible for scanning ports by using nmap

"""
from tools.common.scan_task import ScanTask
from aucote_cfg import cfg
from .base import NmapBase


class PortsScan(ScanTask):
    """
    This class is responsible for scanning node

    """

    def __init__(self, ipv6, udp, tcp):
        self.ipv6 = ipv6
        self.udp = udp
        self.tcp = tcp
        super(PortsScan, self).__init__(NmapBase())

    def prepare_args(self, nodes):
        args = ['-sV', '--script', 'banner']

        if self.ipv6:
            args.append('-6')

        if self.tcp:
            args.append('-sS')

        if self.udp:
            args.append('-sU')

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        include_ports = ",".join(cfg['portdetection.ports.include']) or ""
        args.extend(('-p', include_ports, '--max-rate', str(cfg['portdetection.network_scan_rate'])))

        exclude_ports = cfg['portdetection.ports.exclude']

        if exclude_ports:
            args.extend(['--exclude-ports', ",".join(exclude_ports) or ""])

        args.extend([str(node.ip) for node in nodes])
        return args
