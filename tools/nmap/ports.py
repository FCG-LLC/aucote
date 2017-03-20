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

    def __init__(self):
        super(PortsScan, self).__init__(NmapBase())

    @classmethod
    def prepare_args(cls, nodes):
        args = ['-sV', '--script', 'banner', '-6']

        scripts_dir = cfg['tools.nmap.scripts_dir']

        if scripts_dir:
            args.extend(["--datadir", scripts_dir])

        args.extend(('-p', str(cfg.get('service.scans.ports')),
                     '--max-rate', str(cfg.get('service.scans.network_scan_rate'))
                     ))

        args.extend([str(node.ip) for node in nodes])
        return args
