import time

from structs import Vulnerability, Scan
from tools.common.port_task import PortTask


class AucoteActiveDirectoryTask(PortTask):
    def __init__(self, domain, nodes, *args, **kwargs):
        self.domain = domain
        self.nodes = nodes
        super(AucoteActiveDirectoryTask, self).__init__(*args, **kwargs)

    def _prepare(self):
        self._port.scan = Scan()
        self.aucote.storage.save_security_scans(exploits=self.current_exploits, port=self._port, scan=self._scan)

    def _clean(self):
        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

    async def execute(self, *args, **kwargs):
        exploit = self.aucote.exploits.find('aucote-active-directory', 'aucote-active-directory')
        nodes = "\n".join(" - {0}".format(node.ip) for node in self.nodes)
        output = "Active Directory Controllers from {0} for {1}:\n{2}".format(self.port.node.ip, self.domain, nodes)
        vuln = Vulnerability(port=self.port, output=output, exploit=exploit, context=self.context)
        self.store_vulnerability(vuln)
