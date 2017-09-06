"""
Scanner is responsible for performing port detection scans

"""


import ipaddress
import logging as log

import time

import netifaces

from aucote_cfg import cfg
from database.serializer import Serializer
from scans.executor import Executor
from scans.scan_async_task import ScanAsyncTask
from structs import ScanStatus, PhysicalPort, Scan, TransportProtocol, PortDetectionChange
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan
from tools.nmap.tool import NmapTool


class Scanner(ScanAsyncTask):
    """
    Scanner is responsible for performing port detection scans

    """
    PROTOCOL = TransportProtocol.TCP
    IPV4 = "IPv4"
    IPV6 = "IPv6"

    def __init__(self, as_service=True, *args, **kwargs):
        super(Scanner, self).__init__(*args, **kwargs)

        self.as_service = as_service

    async def run(self):
        """
        Scan nodes for open ports

        Returns:
            None

        """
        self._shutdown_condition.clear()
        self.scan_start = time.time()
        log.info("Starting port scan")
        await self.update_scan_status(ScanStatus.IN_PROGRESS)

        scan = Scan(self.scan_start, protocol=self.PROTOCOL, scanner='scan')
        self.storage.save_scan(scan)

        nodes = await self._get_nodes_for_scanning(timestamp=None, filter_out_storage=True, scan=scan)
        if not nodes:
            log.warning("List of nodes is empty")
            return
        log.debug("Found %i nodes for potential scanning", len(nodes))

        self.storage.save_nodes(nodes, scan=scan)
        self.current_scan = nodes

        await self.run_scan(nodes, scan_only=self.as_service, scanners=self.scanners, protocol=self.PROTOCOL, scan=scan)

        self.current_scan = []

        scan.end = time.time()
        self.storage.update_scan(scan)
        self.diff_with_last_scan(scan)

        await self._clean_scan()

    async def run_scan(self, nodes, scanners, scan, protocol=PROTOCOL, scan_only=False):
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

        port_range_allow = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.include'],
                                                    udp=cfg['portdetection.udp.ports.include'])

        port_range_deny = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.exclude'],
                                                   udp=cfg['portdetection.udp.ports.exclude'])

        ports = [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]

        ports.extend(self._get_special_ports())

        await Executor(aucote=self.aucote, nodes=nodes, ports=ports, scan_only=scan_only, scan=scan)()

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
                self.NAME: {
                    'status': {
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
            data['portdetection'][self.NAME]['status']['previous_scan_duration'] = int(time.time() - self.scan_start)

        await cfg.toucan.push_config(data, overwrite=True)

    @property
    def scanners(self):
        """
        Scanners for port scanning. The return value should be dictionary with keys: self.IPv4, self.IPv6.
        Values should be list of PortScanTasks

        Returns:
            dict

        """
        raise NotImplementedError()

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

    def diff_with_last_scan(self, scan):
        """
        Differentiate two last scans.

        Obtain nodes scanned in current scan. For each node check what changed in port state from last scan of this node

        Args:
            scan (Scan):

        Returns:
            None

        """
        nodes = self.storage.get_nodes_by_scan(scan=scan)
        changes = []

        for node in nodes:
            last_scans = self.storage.get_scans_by_node(node=node, scan=scan)
            current_ports = set(self.storage.get_ports_by_scan_and_node(node=node, scan=scan))

            if len(last_scans) < 2:
                previous_ports = set()
            else:
                previous_ports = set(self.storage.get_ports_by_scan_and_node(node=node, scan=last_scans[1]))

            new_ports = current_ports - previous_ports
            removed_ports = previous_ports - current_ports

            changes.extend(PortDetectionChange(change_time=time.time(), previous_finding=None,
                                               current_finding=port) for port in new_ports)

            changes.extend(PortDetectionChange(current_finding=None, change_time=time.time(),
                                               previous_finding=port) for port in removed_ports)

        self.storage.save_changes(changes)
        for change in changes:
            self.aucote.kudu_queue.send_msg(Serializer.serialize_vulnerability_change(change))
