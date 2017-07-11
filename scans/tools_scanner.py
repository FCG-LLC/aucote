import logging as log

from scans.executor import Executor
from scans.scan_task import ScanTask
from structs import TransportProtocol


class ToolsScanner(ScanTask):
    NAME = "tools"
    PROTOCOL = TransportProtocol.ALL

    async def __call__(self):
        """
        Run scan by using tools and historical port data

        Returns:
            None

        """
        log.info("Starting security scan")
        nodes = await self._get_topdis_nodes()
        ports = self.get_ports_for_scan(nodes)
        log.debug("Ports for security scan: %s", ports)
        self.aucote.add_async_task(Executor(aucote=self.aucote, ports=ports))
