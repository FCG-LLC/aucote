"""
This module contains class responsible for scanning ports by using nmap

"""
from tools.common.scan_task import ScanTask
from aucote_cfg import cfg
from .base import NmapBase
from utils.config import Config

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
        args = []

        if self.ipv6:
            args.append('-6')

        if self.tcp:
            args.append('-sS')

        if self.udp:
            args.extend(('-sU', '--max-retries', '2', '--min-parallelism', '100'))

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        include_ports = cfg['portdetection.ports.include']
        if isinstance(include_ports, (Config, list)):
            include_ports = ",".join(include_ports)

        if include_ports:
            args.extend(['-p', include_ports])

        args.extend(('--max-rate', str(cfg['portdetection.network_scan_rate'])))

        exclude_ports = cfg['portdetection.ports.exclude']

        if isinstance(exclude_ports, (Config, list)):
            exclude_ports = ",".join(exclude_ports)

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend([str(node.ip) for node in nodes])
        return args
