from scans.tasks import NmapPortScanTask
from structs import RiskLevel
from tools.base import Tool
from tools.nmap.base import InfoNmapScript, VulnNmapScript


class NmapTool(Tool):
    def __call__(self, *args, **kwargs):

        tasks = []
        for exploit in self.exploits:
            name = exploit.name
            args = self.config.get('services', {}).get(name, {}).get('args', None)
            if exploit.risk_level == RiskLevel.NONE:
                task = InfoNmapScript(exploit=exploit, port=self.port, name=name, args=args)
            else:
                task = VulnNmapScript(exploit=exploit, port=self.port, name=name, args=args)
            tasks.append(task)

        self.executor.add_task(NmapPortScanTask(executor=self.executor, port=self.port, script_classes=tasks))