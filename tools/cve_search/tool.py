"""
CVESearch is module which request to CVE server about vulnerabilities base on application name and version

"""
from tools.base import Tool
from tools.cve_search.tasks import CVESearchServiceTask


class CVESearchTool(Tool):
    """
    Manage vulnerability searches

    """
    def call(self, *args, **kwargs):
        self.aucote.add_task(CVESearchServiceTask(aucote=self.aucote, port=self.port,
                                                  exploits=[self.aucote.exploits.find('cve-search', 'cve-search')]))
