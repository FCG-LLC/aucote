"""
Provides class for scanning ports

"""
from tools.common.scan_task import ScanTask
from tools.masscan.base import MasscanBase
from aucote_cfg import cfg


class MasscanPorts(ScanTask):
    """
    Scans for open ports using masscan application

    """

    def __init__(self):
        super(MasscanPorts, self).__init__(MasscanBase())

    @classmethod
    def prepare_args(cls, nodes):
        """
        Prepare args for command execution

        Args:
            nodes (list): nodes from scanning

        Returns:
            list

        """
        args = ['--rate', str(cfg.get('service.scans.network_scan_rate')),
                '--ports', str(cfg.get('service.scans.ports')),
                # '--exclude-ports', 'U:0-65535',
                ]

        args.extend([str(node.ip) for node in nodes])

        return args
