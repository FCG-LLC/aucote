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
            singular = self.config.get('services', {}).get(name, {}).get('singular', False)

            if callable(args):
                try:
                    args = args()
                except ImproperConfigurationException as exception:
                    log.warning("{0} is not configured!".format(name), exc_info=exception)
                    continue

            if not isinstance(args, (list, set)):
                args = [args]

            for arg in args:
                if exploit.risk_level == RiskLevel.NONE:
                    task = InfoNmapScript(exploit=exploit, port=self.port, name=name, args=arg)
                else:
                    task = VulnNmapScript(exploit=exploit, port=self.port, name=name, args=arg)

                if singular:
                    self.executor.add_task(NmapPortScanTask(executor=self.executor, port=self.port,
                                                            script_classes=[task]))
                    continue
                tasks.append(task)

        names = []
        scripts = []

        for task in tasks:
            create_new = True
            for i in range(len(names)):
                name = names[i]
                if task.name not in name:
                    name.add(task.name)
                    scripts[i].add(task)
                    create_new = False
                    break

            if create_new:
                names.append({task.name})
                scripts.append({task})

        for script in scripts:
            self.executor.add_task(NmapPortScanTask(executor=self.executor, port=self.port, script_classes=script))

    @classmethod
    def custom_args_dns_zone_transfer(cls):
        try:
            domains = cfg.get('tools.nmap.domains').cfg
            return ['dns-zone-transfer.domain={0}'.format(domain) for domain in domains]
        except KeyError:
            raise ImproperConfigurationException("Please configure your domains in: tools.nmap.domains")

    @classmethod
    def custom_args_dns_srv_enum(cls):
        try:
            domains = cfg.get('tools.nmap.domains').cfg
            return ['dns-srv-enum.domain={0}'.format(domain) for domain in domains]
        except KeyError:
            raise ImproperConfigurationException("Please configure your domains in: tools.nmap.domains")
