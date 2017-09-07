from structs import Vulnerability
from tools.common.port_task import PortTask


class AucoteActiveDirectoryTask(PortTask):
    def __init__(self, domain, nodes, *args, **kwargs):
        self.domain = domain
        self.nodes = nodes
        super(AucoteActiveDirectoryTask, self).__init__(*args, **kwargs)

    async def __call__(self, *args, **kwargs):
        exploit = self.aucote.exploits.find('aucote-active-directory', 'aucote-active-directory')
        nodes = "\n".join(f" - {node.ip}" for node in self.nodes)
        output = f"Active Directory Controllers from {self.port.node.ip} for {self.domain}:\n{nodes}"
        vuln = Vulnerability(port=self.port, output=output, exploit=exploit)
        self.store_vulnerability(vuln)
