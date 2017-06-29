import ipaddress
import logging as log

import time

from tornado.locks import Event

from aucote_cfg import cfg
from scans.executor import Executor
from scans.scan_task import ScanTask
from structs import ScanStatus


class Scanner(ScanTask):
    def __init__(self, *args, **kwargs):
        super(Scanner, self).__init__(*args, **kwargs)
        self._shutdown_condition = Event()
        self.scan_start = None
        self._current_scan = []

    @property
    def scanners(self):
        raise NotImplementedError

    async def __call__(self):
        if not cfg['portdetection.{0}.scan_enabled'.format(self.NAME)]:
            return
        log.info("Starting scanner: %s", self.NAME)
        nodes = await self._get_nodes_for_scanning(timestamp=None)
        log.debug("Found %i nodes for potential scanning", len(nodes))
        await self.run_scan(nodes=nodes, scan_only=self._scan_only)

    async def run_scan(self, nodes, scan_only):
        """
        Run scanning.

        Returns:
            None

        """
        self._shutdown_condition.clear()
        self.scan_start = time.time()
        ports = []

        await self.update_scan_status(ScanStatus.IN_PROGRESS)
        self._current_scan = nodes

        if not nodes:
            log.warning("List of nodes is empty")
            await self._clean_scan()
            return

        self.storage.save_nodes(nodes)

        nodes = {
            self.IPV4: [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)],
            self.IPV6: [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]
        }

        log.info('Scanning nodes (IPv4: %s, IPv6: %s)', len(nodes[self.IPV4]), len(nodes[self.IPV6]))

        for scanner in self.scanners[self.IPV4]:
            log.info("Scanning %i IPv4 nodes for open ports with %s.", len(nodes[self.IPV4]), scanner)
            ports.extend(await scanner.scan_ports(nodes[self.IPV4]))

        for scanner in self.scanners[self.IPV6]:
            log.info("Scanning %i IPv6 nodes for open ports with %s.", len(nodes[self.IPV6]), scanner)
            ports.extend(await scanner.scan_ports(nodes[self.IPV6]))

        ports = self._filter_out_ports(ports)
        ports.extend(self._get_special_ports())

        self.aucote.add_async_task(Executor(aucote=self.aucote, ports=ports, scan_only=scan_only))
        await self._clean_scan()

    async def _clean_scan(self):
        """
        Clean scan and update scan status

        Returns:
            None

        """
        await self.update_scan_status(ScanStatus.IDLE)
        self._shutdown_condition.set()
        self._current_scan = []

    async def update_scan_status(self, status):
        """
        Update scan status base on status value

        Args:
            status (ScanStatus):

        Returns:
            None

        """
        if not cfg.toucan:
            return

        data = {
            'portdetection': {
                'status': {
                    self.NAME: {
                        'previous_scan_start': self.previous_scan,
                        'next_scan_start': self.next_scan,
                        'scan_start': self.scan_start,
                        'previous_scan_duration': 0,
                        'code': status.value
                    }
                }
            }
        }

        if status is ScanStatus.IDLE:
            data['portdetection']['status'][self.NAME]['previous_scan_duration'] = int(time.time() - self.scan_start)

        await cfg.toucan.push_config(data, overwrite=True)

    @property
    def current_scan(self):
        """
        List of currently scan nodes

        Returns:
            list

        """
        return self._current_scan[:]
