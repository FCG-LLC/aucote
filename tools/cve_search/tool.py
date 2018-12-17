"""
CVESearch is module which requests CVE server for vulnerabilities basing on application name and version

"""

from structs import PhysicalPort, TaskManagerType
from tools.base import Tool
from tools.cve_search.tasks import CVESearchServiceTask


class CVESearchTool(Tool):
    """
    Manage vulnerability searches

    """
    def __init__(self, node=None, port=None, *args, **kwargs):
        self.node = node
        super(CVESearchTool, self).__init__(port=port, *args, **kwargs)

    async def call(self, *args, **kwargs):
        if not self.port:
            self.port = PhysicalPort(node=self.node)

        self.context.add_task(CVESearchServiceTask(context=self.context, port=self.port,
                                                   exploits=[self.aucote.exploits.find('cve-search', 'cve-search')]),
                              manager=TaskManagerType.QUICK)

    def additional_info(self):
        return "on {port}".format(port=self.port if self.port else self.node)
