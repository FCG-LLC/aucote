"""
CVESearch is module which requests CVE server for vulnerabilities basing on application name and version

"""

from structs import PhysicalPort, Scan
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
            self.port.scan = Scan()

        self.aucote.add_async_task(CVESearchServiceTask(aucote=self.aucote, port=self.port, scan=self._scan,
                                                        exploits=[self.aucote.exploits.find('cve-search',
                                                                                            'cve-search')]))

    def __str__(self):
        return "{name} on {port}".format(name=type(self).__name__, port=self.port if self.port else self.node)
