"""
Provides class for scanning ports

"""
from tools.common.scan_task import ScanTask
from tools.masscan.base import MasscanBase
from aucote_cfg import cfg
from utils.config import Config


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
        args = ['--rate', str(cfg['portdetection.network_scan_rate']),
                # '--exclude-ports', 'U:0-65535'
               ]

        include_ports = cfg['portdetection.ports.include']

        if isinstance(include_ports, Config):
            include_ports = ",".join(include_ports)

        if include_ports:
            args.extend(['--ports', include_ports])

        exclude_ports = cfg['portdetection.ports.exclude']

        if isinstance(exclude_ports, Config):
            exclude_ports = ",".join(exclude_ports)

        if exclude_ports:
            args.extend(['--exclude-ports', exclude_ports])

        args.extend([str(node.ip) for node in nodes])

        return args
