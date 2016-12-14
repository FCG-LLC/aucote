"""
Contains main class responsible for managing NMAP

"""
import logging as log

from aucote_cfg import cfg
from structs import RiskLevel
from tools.base import Tool
from tools.nmap.base import InfoNmapScript, VulnNmapScript
from tools.nmap.tasks.port_scan import NmapPortScanTask
from utils.exceptions import ImproperConfigurationException


class NmapTool(Tool):
    """
    It's responsible for managing and executing nmap tasks

    """

    def call(self, *args, **kwargs):
        """
        Prepares nmap args, executes and manages nmap scripts.

        If there is a list of different arguments and this same script name, they shouldn't be executed together

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        tasks = self._get_tasks()

        names = []
        scripts = []

        for task in tasks:
            create_new = True
            for i, name in enumerate(names):
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

    def _get_tasks(self):
        """
        Prepare nmaps scripts  for executing

        Returns:
            list - list of tasks
        """
        tasks = []

        disabled_scripts = self.config.get('disable_scripts', set()).copy()
        disabled_scripts.update(set(cfg.get('tools.nmap.disable_scripts').cfg or []))

        for exploit in self.exploits:
            name = exploit.name

            if name in disabled_scripts:
                continue

            service_args = self.config.get('services', {}).get(self.port.service_name, {}).get('args', None)

            if callable(service_args):
                service_args = service_args()
            else:
                service_args = ""


            args = self.config.get('scripts', {}).get(name, {}).get('args', None)
            singular = self.config.get('scripts', {}).get(name, {}).get('singular', False)

            if callable(args):
                try:
                    args = args()
                except ImproperConfigurationException as exception:
                    log.warning("%s is not configured: Please configure %s in %s", name, exception,
                                cfg.get('config_filename'))
                    continue

            if not isinstance(args, (list, set)):
                args = [args]

            for arg in args:
                arg = "{0},{1}".format(arg or "", service_args).strip(",")

                if exploit.risk_level == RiskLevel.NONE:
                    task = InfoNmapScript(exploit=exploit, port=self.port, name=name, args=arg)
                else:
                    task = VulnNmapScript(exploit=exploit, port=self.port, name=name, args=arg)

                if singular:
                    self.executor.add_task(NmapPortScanTask(executor=self.executor, port=self.port,
                                                            script_classes=[task]))
                    continue
                tasks.append(task)

        return tasks

    @classmethod
    def custom_args_dns_zone_transfer(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            list

        """
        domains = cls.get_config('tools.nmap.domains')
        return ['dns-zone-transfer.domain={0}'.format(domain) for domain in domains]

    @classmethod
    def custom_args_dns_srv_enum(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            list

        """
        domains = cls.get_config('tools.nmap.domains')
        return ['dns-srv-enum.domain={0}'.format(domain) for domain in domains]

    @classmethod
    def custom_args_dns_check_zone(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            list

        """
        domains = cls.get_config('tools.nmap.domains')
        return ['dns-check-zone.domain={0}'.format(domain) for domain in domains]

    @classmethod
    def custom_args_http_domino_enum_passwords(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            str

        """
        config = cls.get_config('tools.nmap.domino-http')
        return "domino-enum-passwords.username='{0}',domino-enum-passwords.password={1}".format(
            config.get('username', None), config.get('password', None))

    @classmethod
    def custom_args_http_useragent(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            str

        """
        config = cfg.get('service.scans.useragent')
        if config:
            return "http.useragent='{0}'".format(config)
