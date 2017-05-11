"""
CVESearch is module which request to CVE server about vulnerabilities base on application name and version

"""
from structs import PhysicalPort
from tools.base import Tool
from tools.cve_search.tasks import CVESearchServiceTask
import logging as log


class CVESearchTool(Tool):
    """
    Manage vulnerability searches

    """
    def __init__(self, node=None, port=None, *args, **kwargs):
        self.node = node
        super(CVESearchTool, self).__init__(port=port, *args, **kwargs)

    def call(self, *args, **kwargs):
        if not self.port:
            self.port = PhysicalPort(node=self.node)

        self.aucote.add_task(CVESearchServiceTask(aucote=self.aucote, port=self.port,
                                                  exploits=[self.aucote.exploits.find('cve-search', 'cve-search')]))
