"""
This module contains class responsible for scanning ports by using nmap

"""
from aucote_cfg import cfg
from tools.nmap.tool import NmapTool
from tools.common.port_scan_task import PortScanTask
from utils.exceptions import StopCommandException
from utils.time import parse_period
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

    async def prepare_args(self, nodes):
        args = ['-Pn']

        base_rate = cfg['portdetection.tcp.scan_rate'] if self.tcp else cfg['portdetection.udp.scan_rate']
        throttling = await cfg.toucan.get('throttling.rate', add_prefix=False) if cfg.toucan is not None else 1

        if throttling > 1:
            throttling = 1

        if throttling < 0:
            throttling = 0

        rate = str(int(float(throttling) * int(base_rate)))

        if rate == '0':
            raise StopCommandException("Cancel scan due to low throttling rate {}".format(throttling))

        if self.ipv6:
            args.append('-6')

        if self.tcp:
            args.extend(['-sS', '--host-timeout', str(parse_period(str(cfg['portdetection.tcp.host_timeout'])))])

        if self.udp:
            if cfg['portdetection.udp.defeat_icmp_ratelimit']:
                args.extend(('--min-rate', rate, '--defeat-icmp-ratelimit'))

            args.extend(('-sU', '--max-retries', str(cfg['portdetection.udp.max_retries'])))

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
