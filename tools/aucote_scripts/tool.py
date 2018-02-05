from structs import PhysicalPort, Scan
from tools.aucote_scripts.tasks.siet import SietTask
from tools.base import Tool
from tools.cve_search.tasks import CVESearchServiceTask


class AucoteScriptsTool(Tool):

    def __init__(self, node=None, port=None, *args, **kwargs):
        self.node = node
        super(AucoteScriptsTool, self).__init__(port=port, *args, **kwargs)

    async def call(self, *args, **kwargs):
        if not self.port:
            return

        self.context.add_task(SietTask(context=self.context, port=self.port, scan=self._scan,
                                       exploits=self.exploits.find('aucote-scripts', 'siet')))
