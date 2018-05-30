from fixtures.exploits import Exploit
from tools.aucote_scripts.tasks.siet import SietTask
from tools.base import Tool
from utils.exceptions import PortNotSpecifiedException


class AucoteScriptsTool(Tool):

    def __init__(self, node=None, port=None, *args, **kwargs):
        self.node = node
        super(AucoteScriptsTool, self).__init__(port=port, *args, **kwargs)

    async def call(self, *args, **kwargs):
        if not self.port:
            raise PortNotSpecifiedException()

        if Exploit(exploit_id=178) in self.exploits:
            self.context.add_task(SietTask(context=self.context, port=self.port, scan=self._scan,
                                           exploits=[self.context.aucote.exploits.find('aucote-scripts', 'siet')]))
