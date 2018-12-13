"""
CiscoAPIs is a tool which provides CiscoAPIS functionality

"""

from structs import PhysicalPort
from tools.base import Tool
from tools.ciscoapis.tasks import CiscoApisPsirtTask
from tools.cve_search.tasks import CVESearchServiceTask


class CiscoApisTool(Tool):
    """
    Manage vulnerability searches

    """
    def __init__(self, node=None, port=None, *args, **kwargs):
        self.node = node
        super().__init__(port=port, *args, **kwargs)

    async def call(self, *args, **kwargs):
        if not self.port:
            self.port = PhysicalPort(node=self.node)

        self.context.add_task(CiscoApisPsirtTask(context=self.context, port=self.port,
                                                 exploits=[self.aucote.exploits.find('ciscoapis', 'psirt')]),
                              manager=self.aucote.TASK_MANAGER_QUICK)

    def additional_info(self):
        return "on {port}".format(port=self.port if self.port else self.node)
