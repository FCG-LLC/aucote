from structs import RiskLevel
from tools.base import Tool
from tools.nmap.base import InfoNmapScript, VulnNmapScript
from tools.nmap.tasks.port_scan import NmapPortScanTask
from aucote_cfg import cfg
from utils.exceptions import ImproperConfigurationException
import logging as log


class NmapTool(Tool):
    """
    It's responsible for managing and executing nmap tasks

    """

    def __call__(self, *args, **kwargs):
        """
        Prepares nmap args, executes and manages nmap scripts.

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """

        tasks = []
        for exploit in self.exploits:
            name = exploit.name
            args = self.config.get('services', {}).get(name, {}).get('args', None)

            if callable(args):
                try:
                    args = args()
                except ImproperConfigurationException as exception:
                    log.warning("{0} is not configured!".format(name), exc_info=exception)
                    continue

            if exploit.risk_level == RiskLevel.NONE:
                task = InfoNmapScript(exploit=exploit, port=self.port, name=name, args=args)
            else:
                task = VulnNmapScript(exploit=exploit, port=self.port, name=name, args=args)
            tasks.append(task)

        self.executor.add_task(NmapPortScanTask(executor=self.executor, port=self.port, script_classes=tasks))

    @classmethod
    def custom_args_dns_zone_transfer(cls):
        try:
            return 'dns-zone-transfer.domain={0}'.format(cfg.get('tools.nmap.domain'))
        except KeyError:
            raise ImproperConfigurationException("Please configure your domains in: tools.nmap.domain")
