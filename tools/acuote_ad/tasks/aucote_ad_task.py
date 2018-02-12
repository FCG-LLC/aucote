from structs import Vulnerability
from tools.common.port_task import PortTask


class AucoteActiveDirectoryTask(PortTask):
    def __init__(self, domain, nodes, *args, **kwargs):
        self.domain = domain
        self.nodes = nodes
        super(AucoteActiveDirectoryTask, self).__init__(*args, **kwargs)

    async def __call__(self, *args, **kwargs):
        exploit = self.aucote.exploits.find('aucote-active-directory', 'aucote-active-directory')
        nodes = "\n".join(" - {0}".format(node.ip) for node in self.nodes)
        output = "Active Directory Controllers from {0} for {1}:\n{2}".format(self.port.node.ip, self.domain, nodes)
        vuln = Vulnerability(port=self.port, output=output, exploit=exploit, context=self.context)
        self.store_vulnerability(vuln)
