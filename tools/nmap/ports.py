"""
This module contains class responsible for scanning ports by using nmap

"""
from aucote_cfg import cfg
from tools.nmap.tool import NmapTool
from tools.common.port_scan_task import PortScanTask
from utils.exceptions import StopCommandException
from .base import NmapBase


class PortsScan(PortScanTask):
    """
    This class is responsible for scanning node

    """

    def __init__(self, ipv6, udp, tcp):
        self.ipv6 = ipv6
        self.udp = udp
        self.tcp = tcp
        super(PortsScan, self).__init__(NmapBase())

    def prepare_args(self, nodes):
        args = ['-Pn']
        rate = str(cfg['portdetection.network_scan_rate'])

        if self.ipv6:
            args.append('-6')

        if self.tcp:
            args.extend(['-sS', '--host-timeout', str(cfg['portdetection._internal.host_timeout'])])

        if self.udp:
            args.extend(('-sU', '--min-rate', rate, '--max-retries', str(cfg['portdetection._internal.udp_retries']),
                         '--defeat-icmp-ratelimit'))

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        include_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.tcp.ports.include'],
                                                      udp=self.udp and cfg['portdetection.udp.ports.include'])

        exclude_ports = NmapTool.list_to_ports_string(tcp=self.tcp and cfg['portdetection.tcp.ports.exclude'],
                                                      udp=self.udp and cfg['portdetection.udp.ports.exclude'])

        if not include_ports:
            raise StopCommandException("No ports for scan")
        args.extend(['-p', include_ports])

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend(('--max-rate', rate))

        args.extend([str(node.ip) for node in nodes])
        return args
