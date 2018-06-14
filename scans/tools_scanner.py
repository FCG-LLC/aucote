"""
Scanner dedicated for tools.

"""

import logging as log

import time

from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from scans.executor import Executor
from scans.scan_async_task import ScanAsyncTask
from structs import Scan, ScanStatus


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
        try:
            self.scan_start = int(time.time())
            await self.update_scan_status(ScanStatus.IN_PROGRESS)
            self.shutdown_condition.clear()
            log.info("Starting security scan")
            last_scan_start = self.get_last_scan_start()

            scan = Scan(time.time(), protocol=self.PROTOCOL, scanner=self.NAME)

            nodes = await self._get_nodes_for_scanning(timestamp=last_scan_start, scan=scan, filter_out_storage=False)
            self.storage.save_scan(scan)
            self.storage.save_nodes(nodes, scan=scan)

            ports = self.get_ports_for_scan(nodes, timestamp=last_scan_start)
            log.debug("Ports for security scan: %s", ports)
            self.context.add_task(Executor(context=self.context, nodes=nodes if cfg['portdetection.{0}.scan_nodes'.
                                           format(self.NAME)] else None, ports=ports, scan=scan, scanner=self))

            await self.context.wait_on_tasks_finish()

            scan.end = time.time()
            self.storage.update_scan(scan)
        except (HTTPError, ConnectionError) as exception:
            log.error('Cannot connect to topdis: %s, %s', self.topdis.api, exception)
        finally:
            await self._clean_scan()

    def get_ports_for_scan(self, nodes, timestamp=None):
        """
        Get ports for scanning. Topdis node data combined with stored open ports data.

        Returns:
            list

            """
        return list(set(self.storage.get_ports_by_nodes(nodes=nodes, timestamp=timestamp, protocol=self.PROTOCOL,
                                                        portdetection_only=True)))

    def get_last_scan_start(self):
        scans = self.storage.get_scans(self.PROTOCOL, self.NAME, amount=1)
        if not scans:
            return 0
        return scans[0].start
