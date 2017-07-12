import ipaddress
import logging as log

import time

import netifaces

from aucote_cfg import cfg
from scans.executor import Executor
from scans.scan_async_task import ScanAsyncTask
from structs import ScanStatus, PhysicalPort, Scan, TransportProtocol
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
from tools.nmap.tool import NmapTool


class Scanner(ScanAsyncTask):
    PROTOCOL = TransportProtocol.TCP

    def __init__(self, as_service=True, *args, **kwargs):
        super(Scanner, self).__init__(*args, **kwargs)

        self.as_service = as_service

    async def __call__(self):
        """
        Scan nodes for open ports

        Returns:
            None

        """
        if not cfg['portdetection.scan_enabled']:
            return
        log.info("Starting port scan")
        nodes = await self._get_nodes_for_scanning(timestamp=None, protocol=self.PROTOCOL, filter_out_storage=True)
        log.debug("Found %i nodes for potential scanning", len(nodes))

        await self.run_scan(nodes, scan_only=self.as_service)

    async def run_scan(self, nodes, scan_only=False):
        """
        Run scanning.

        Returns:
            None

        """
        self._shutdown_condition.clear()
        self.scan_start = time.time()
        await self.update_scan_status(ScanStatus.IN_PROGRESS)

        nmap_udp = cfg['portdetection._internal.nmap_udp']

        self.current_scan = nodes

        if not nodes:
            log.warning("List of nodes is empty")
            await self._clean_scan()
            return

        self.storage.save_nodes(nodes, protocol=self.PROTOCOL)

        nodes_ipv4 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)]
        nodes_ipv6 = [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]

        log.info('Scanning %i nodes (IPv4: %s, IPv6: %s)', len(nodes), len(nodes_ipv4), len(nodes_ipv6))

        log.info("Scanning %i IPv4 nodes for open ports.", len(nodes_ipv4))
        scanner_ipv4 = MasscanPorts(udp=not nmap_udp)
        ports = await scanner_ipv4.scan_ports(nodes_ipv4)

        log.info("Scanning %i IPv6 nodes for open ports.", len(nodes_ipv6))
        scanner_ipv6 = PortsScan(ipv6=True, tcp=True, udp=True)
        ports_ipv6 = await scanner_ipv6.scan_ports(nodes_ipv6)
        ports.extend(ports_ipv6)

        if nmap_udp:
            log.info("Scanning %i IPv4 nodes for open UDP ports.", len(nodes_ipv4))
            scanner_ipv4_udp = PortsScan(ipv6=False, tcp=False, udp=True)
            ports_udp = await scanner_ipv4_udp.scan_ports(nodes_ipv4)
            ports.extend(ports_udp)

        port_range_allow = NmapTool.ports_from_list(tcp=cfg['portdetection.ports.tcp.include'],
                                                    udp=cfg['portdetection.ports.tcp.include'])

        port_range_deny = NmapTool.ports_from_list(tcp=cfg['portdetection.ports.tcp.exclude'],
                                                   udp=cfg['portdetection.ports.tcp.exclude'])

        ports = [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]

        if cfg['service.scans.physical']:
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addr = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addr:
                    continue

                port = PhysicalPort()
                port.interface = interface
                port.scan = Scan(start=time.time())
                ports.append(port)

        self.aucote.add_async_task(Executor(aucote=self.aucote, nodes=nodes, ports=ports, scan_only=scan_only))
        self.current_scan = []

        await self._clean_scan()

    async def _clean_scan(self):
        """
        Clean scan and update scan status

        Returns:
            None

        """
        await self.update_scan_status(ScanStatus.IDLE)
        self._shutdown_condition.set()

        if not self.as_service:
            await self.aucote.async_task_manager.stop()

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
                    'previous_scan_start': self.previous_scan,
                    'next_scan_start': self.next_scan,
                    'scan_start': self.scan_start,
                    'previous_scan_duration': 0,
                    'code': status.value
                }
            }
        }

        if status is ScanStatus.IDLE:
            data['portdetection']['status']['previous_scan_duration'] = int(time.time() - self.scan_start)

        await cfg.toucan.push_config(data, overwrite=True)
