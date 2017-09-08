"""
Scanner dedicated for tools.

"""

import logging as log

import time
from croniter import croniter

from aucote_cfg import cfg
from scans.executor import Executor
from scans.scan_async_task import ScanAsyncTask
from structs import Scan


class ToolsScanner(ScanAsyncTask):
    """
    Scanner dedicated for tools.

    """
    PROTOCOL = None
    NAME = None

    def __init__(self, name, *args, **kwargs):
        super(ToolsScanner, self).__init__(*args, **kwargs)
        self.NAME = name

    async def run(self):
        """
        Run scan by using tools and historical port data

        Returns:
            None

        """
        log.info("Starting security scan")

        scan = Scan(time.time(), protocol=self.PROTOCOL, scanner='tools scan')
        self.storage.save_scan(scan)

        nodes = await self._get_nodes_for_scanning(timestamp=None, scan=scan, filter_out_storage=False)
        self.storage.save_nodes(nodes, scan=scan)

        ports = self.get_ports_for_scan(nodes)
        log.debug("Ports for security scan: %s", ports)
        self.aucote.add_async_task(Executor(aucote=self.aucote, nodes=nodes if cfg['portdetection.{0}.scan_nodes'.
                                            format(self.NAME)] else None, ports=ports, scan=scan, scanner=self))

        scan.end = time.time()
        self.storage.update_scan(scan)

    def get_ports_for_scan(self, nodes):
        """
        Get ports for scanning. Topdis node data combined with stored open ports data.

        Returns:
            list

            """
        return self.storage.get_ports_by_nodes(nodes=nodes, timestamp=self.previous_scan, protocol=self.PROTOCOL)
