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
    IPV4 = "IPv4"
    IPV6 = "IPv6"

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

        self._shutdown_condition.clear()
        self.scan_start = time.time()
        log.info("Starting port scan")
        await self.update_scan_status(ScanStatus.IN_PROGRESS)

        for protocol, scanners in self.scanners.items():
            scan = Scan(self.scan_start)
            self.storage.save_scan(scan)

            nodes = await self._get_nodes_for_scanning(timestamp=None, filter_out_storage=True, protocol=protocol)
            if not nodes:
                log.warning("List of nodes is empty")
                continue
            log.debug("Found %i nodes for potential scanning", len(nodes))

            self.storage.save_nodes(nodes, protocol=protocol)
            self.current_scan = nodes

            await self.run_scan(nodes, scan_only=self.as_service, scanners=scanners, protocol=protocol)

            self.current_scan = []

            scan.end = time.time()
            self.storage.update_scan(scan)

        await self._clean_scan()

    async def run_scan(self, nodes, scanners, protocol=PROTOCOL, scan_only=False):
        """
        Run scanning.

        Returns:
            None

        """
        ports = []

        dict_nodes = {
            self.IPV4: [node for node in nodes if isinstance(node.ip, ipaddress.IPv4Address)],
            self.IPV6: [node for node in nodes if isinstance(node.ip, ipaddress.IPv6Address)]
        }
        log.info('Scanning nodes %s: (IPv4: %s, IPv6: %s)', protocol.name, len(dict_nodes[self.IPV4]),
                 len(dict_nodes[self.IPV6]))

        for ip_protocol in dict_nodes:
            for scanner in scanners[ip_protocol]:
                log.info("Scanning %i %s %s nodes for open ports.", len(dict_nodes[ip_protocol]), protocol.name,
                         ip_protocol)
                ports.extend(await scanner.scan_ports(dict_nodes[ip_protocol]))

        port_range_allow = NmapTool.ports_from_list(tcp=cfg['portdetection.ports.tcp.include'],
                                                    udp=cfg['portdetection.ports.udp.include'])

        port_range_deny = NmapTool.ports_from_list(tcp=cfg['portdetection.ports.tcp.exclude'],
                                                   udp=cfg['portdetection.ports.udp.exclude'])

        ports = [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]

        ports.extend(self._get_special_ports())

        self.aucote.add_async_task(Executor(aucote=self.aucote, nodes=nodes, ports=ports, scan_only=scan_only))

    async def _clean_scan(self):
        """
        Clean scan and update scan status

        Returns:
            None

        """
        await self.update_scan_status(ScanStatus.IDLE)
        self._shutdown_condition.set()

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

    @property
    def scanners(self):
        return {
            TransportProtocol.TCP: self._tcp_scanners,
            TransportProtocol.UDP: self._udp_scanners
        }

    @property
    def _tcp_scanners(self):
        return {
            self.IPV4: [MasscanPorts(udp=False)],
            self.IPV6: [PortsScan(ipv6=True, tcp=True, udp=False)]
        }

    @property
    def _udp_scanners(self):
        return {
            self.IPV4: [PortsScan(ipv6=False, tcp=False, udp=True)],
            self.IPV6: [PortsScan(ipv6=True, tcp=False, udp=True)]
        }

    def _get_special_ports(self):
        return_value = []
        if cfg['service.scans.physical']:
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addr = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addr:
                    continue

                port = PhysicalPort()
                port.interface = interface
                port.scan = Scan(start=time.time())
                return_value.append(port)

        return return_value
