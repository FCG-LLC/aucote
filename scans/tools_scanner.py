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

        To achieve resuming scans, the resume is introduced.

        If resume is enabled, last scan is used to grab non scanned nodes, otherwise topdisco is used to refresh data

        Ports are taken from date of last check, which is date of previous finished scan

        If tools scanner is performed without tcp scan between them, then no ports are taken to security scans.
        The problem is than in live scan mode, last tcp scan will have only info limited number of nodes
        """
        try:
            self.scan.start = time.time()

            await self.update_scan_status(ScanStatus.IN_PROGRESS)
            self.shutdown_condition.clear()
            log.info("Starting security scan")

            last_scan = self.get_last_scan()
            last_scan_start = last_scan.start if last_scan is not None else 0

            last_finished_scan = self.get_previous_non_resumed_scan()
            last_finished_scan_start = last_finished_scan.start if last_finished_scan is not None else 0

            if resume:
                log.info('Resuming scan %s with rowid %i', last_scan.scanner, last_scan.rowid)

                if last_finished_scan:
                    log.debug('Taking ports same as scan %s with rowid %i', last_finished_scan.scanner,
                              last_finished_scan.rowid)

            nodes = await self._get_nodes_for_scanning(timestamp=last_scan_start, filter_out_storage=False,
                                                       scan=last_scan if resume else None)

            self.storage.save_scan(self.scan)
            log.debug('Current scan rowid is %s', self.scan.rowid)
            self.storage.save_nodes(nodes, scan=self.scan)

            ports = self.get_ports_for_scan(nodes, timestamp=last_finished_scan_start)
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
