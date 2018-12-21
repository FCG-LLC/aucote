"""
Scanner dedicated for tools.

"""

import logging as log

import time

from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from scans.executor import Executor
from scans.scan_async_task import ScanAsyncTask
from structs import ScanStatus, TaskManagerType


class ToolsScanner(ScanAsyncTask):
    """
    Scanner dedicated for tools.

    """
    PROTOCOL = None
    NAME = None

    def __init__(self, name, *args, **kwargs):
        self.NAME = name  # Set scanner name before initializing parent constructor
        super(ToolsScanner, self).__init__(*args, **kwargs)

    async def run(self, resume=False):
        """
        Run scan by using tools and historical port data

        Returns:
            None

        """
        try:
            self.scan.start = time.time()

            await self.update_scan_status(ScanStatus.IN_PROGRESS)
            self.shutdown_condition.clear()
            log.info("Starting security scan")

            last_scan = self.get_last_scan()
            last_scan_start = last_scan.start if last_scan is not None else 0

            resumed_scan = None

            if resume:
                log.info('Resuming scan %s with rowid %i', last_scan.scanner, last_scan.rowid)

                resumed_scan = self.get_previous_non_resumed_scan()

                if resumed_scan:
                    log.debug('Taking ports same as scan %s with rowid %i', resumed_scan.scanner, resumed_scan.rowid)

            nodes = await self._get_nodes_for_scanning(timestamp=last_scan_start, filter_out_storage=False,
                                                       scan=last_scan if resume else None)
            self.storage.save_scan(self.scan)
            log.debug('Current scan rowid is %s', self.scan.rowid)
            self.storage.save_nodes(nodes, scan=self.scan)

            ports = self.get_ports_for_scan(nodes, timestamp=resumed_scan.start if resumed_scan is not None
                                            else 0)
            log.debug("Ports for security scan: %s", ports)
            self.context.add_task(Executor(context=self.context, nodes=nodes if cfg['portdetection.{0}.scan_nodes'.
                                           format(self.NAME)] else None, ports=ports),
                                  manager=TaskManagerType.QUICK)

            await self.context.wait_on_tasks_finish()

            self.scan.end = time.time()
            self.storage.update_scan(self.scan)
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
