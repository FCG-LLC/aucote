from aucote_cfg import cfg
from tools.base import Tool
from tools.hydra.tasks import HydraScriptTask


class HydraTool(Tool):
    def __call__(self, *args, **kwargs):
        if not cfg.get('tools.hydra.enable'):
            return

        service_name = self.config.get('mapper').get(self.port.service_name, None) or self.port.service_name

        if not service_name in self.config.get('services', set()):
            return

        if service_name in self.config.get('without-login', []):
            login = False
        else:
            login = True

        self.executor.add_task(HydraScriptTask(executor=self.executor, port=self.port, service=service_name,
                                               login=login))