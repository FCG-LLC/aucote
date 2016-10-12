"""
This module provides Hydra main class

"""
from aucote_cfg import cfg
from tools.base import Tool
from tools.hydra.tasks import HydraScriptTask


class HydraTool(Tool):
    """
    This tool is responsible for managing task for Hydra.

    """
    def call(self, *args, **kwargs):
        """
        This function is executed by task manager. Based on configuration adds scan task to the tak manager.

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        service_name = self.config.get('mapper').get(self.port.service_name, None) or self.port.service_name

        if service_name not in self.config.get('services', set()) or \
           self.port.service_name in cfg.get('tools.hydra.disable_services').cfg:
            return

        login = service_name not in self.config.get('without-login', [])

        self.executor.add_task(HydraScriptTask(executor=self.executor, port=self.port, service=service_name,
                                               exploit=self.executor.exploits.find('hydra', 'hydra'), login=login))
