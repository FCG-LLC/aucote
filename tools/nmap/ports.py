"""
This module contains class responsible for scanning ports by using nmap

"""
from tools.common.scan_task import ScanTask
from aucote_cfg import cfg
from tools.nmap.tool import NmapTool
from utils.config import Config
from utils.exceptions import StopCommandException
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
        args = ['-Pn', '--host-timeout', str(cfg['portdetection._internal.host_timeout'])]
        rate = str(cfg['portdetection.network_scan_rate'] if self.tcp else cfg['portdetection.udp_network_scan_rate'])

        if self.ipv6:
            args.append('-6')

        if self.tcp:
            args.append('-sS')

        if self.udp:
            args.extend(('-sU', '--max-retries', str(cfg['portdetection._internal.udp_retries'])))
            if cfg['portdetection._internal.defeat_icmp']:
                args.extend(('--min-rate', rate, '--defeat-icmp-ratelimit'))

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        include_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.ports.tcp.include'],
                                                      udp=self.udp and cfg['portdetection.ports.udp.include'])

        exclude_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.ports.tcp.exclude'],
                                                      udp=self.udp and cfg['portdetection.ports.udp.exclude'])

        if not include_ports:
            raise StopCommandException("No ports for scan")
        args.extend(['-p', include_ports])

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend(('--max-rate', rate))

        args.extend([str(node.ip) for node in nodes])
        return args
