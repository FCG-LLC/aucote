"""
Scanner is responsible for performing port detection scans

"""


import ipaddress
import logging as log

import time

import netifaces

from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from database.serializer import Serializer
from scans.executor import Executor
from scans.scan_async_task import ScanAsyncTask
from structs import ScanStatus, PhysicalPort, Scan, TransportProtocol, PortDetectionChange, TaskManagerType
from tools.nmap.tool import NmapTool
from utils.task import TaskWrapper


class Scanner(ScanAsyncTask):
    """
    Scanner is responsible for performing port detection scans

    """
    PROTOCOL = TransportProtocol.TCP
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    NAME = None

    def __init__(self, as_service=True, *args, **kwargs):
        super(Scanner, self).__init__(*args, **kwargs)

        self.as_service = as_service
        self.nodes = []

    async def run(self, resume=False):
        """
        Scan nodes for open ports

        Returns:
            None

        """
        try:
            self._shutdown_condition.clear()
            self.scan.start = time.time()
            log.info("Starting port scan")

            if resume:
                previous_scan = self.get_last_scan()
                if not previous_scan:
                    log.warning('No scan to resume')
                    return
                log.info('Resuming scan %s with rowid %s', previous_scan.scanner, previous_scan.rowid)
            else:
                previous_scan = None

            nodes = await self._get_nodes_for_scanning(filter_out_storage=True, scan=previous_scan)
            if not nodes:
                log.warning("List of nodes is empty")
                self.scan.start = None
                return

            self.storage.save_scan(self.scan)

            log.debug("Found %i nodes for potential scanning", len(nodes))
            self.nodes = nodes
            await self.update_scan_status(ScanStatus.IN_PROGRESS)

            self.storage.save_nodes(nodes, scan=self.scan)
            self.current_scan = nodes

            await self.run_scan(nodes, scan_only=self.as_service, scanners=self.scanners, protocol=self.PROTOCOL)

            self.current_scan = []

            await self.context.wait_on_tasks_finish()
            self.scan.end = time.time()
            self.storage.update_scan(self.scan)
            self.diff_with_last_scan()
        except (HTTPError, ConnectionError) as exception:
            log.error('Cannot connect to topdis: %s, %s', self.topdis.api, exception)
        finally:
            await self._clean_scan()

    async def run_scan(self, nodes, scanners, protocol=PROTOCOL, scan_only=False):
        """
        Run scanning.

        Returns:
            None

        """
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
                if self.context.cancelled():
                    log.warning('Skip scanning %s:%s because of cancelling scan %s', ip_protocol, protocol.name,
                                self.NAME)
                    continue

                if protocol == TransportProtocol.UDP:
                    task = TaskWrapper(self.context, scanner.scan_ports, dict_nodes[ip_protocol])
                    self.context.add_task(task, TaskManagerType.SCANNER)
                    ports = await task.get_result()

                    await self._scan_ports(ports=ports, scan_only=scan_only)
                else:
                    for node in dict_nodes[ip_protocol]:
                        if self.context.cancelled():
                            log.warning('Skip scanning %s because of cancelling scan %s', node.ip, self.NAME)
                            continue
                        log.debug('Scanning %s by scan %s', node.ip, self.NAME)
                        ports = await scanner.scan_ports([node])
                        log.debug('Found %s ports for %s for scan %s', len(ports), node.ip, self.NAME)
                        await self._scan_ports(ports=ports, scan_only=scan_only)

        self.context.add_task(Executor(context=self.context, nodes=nodes, ports=self._get_special_ports(),
                                       scan_only=scan_only), manager=TaskManagerType.QUICK)

    async def _scan_ports(self, scan_only, ports):

        port_range_allow = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.include'],
                                                    udp=cfg['portdetection.udp.ports.include'])

        port_range_deny = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.exclude'],
                                                   udp=cfg['portdetection.udp.ports.exclude'])

        ports = [port for port in ports if port.in_range(port_range_allow) and not port.in_range(port_range_deny)]

        self.context.add_task(Executor(context=self.context, nodes=[], ports=ports, scan_only=scan_only),
                              manager=TaskManagerType.QUICK)

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

    def diff_with_last_scan(self):
        """
        Differentiate two last scans.

        Obtain nodes scanned in current scan. For each node check what changed in port state from last scan of this node

        Args:
            scan (Scan):

        Returns:
            None

        """
        nodes = self.storage.get_nodes_by_scan(scan=self.scan)
        changes = []

        for node in nodes:
            last_scans = self.storage.get_scans_by_node(node=node, scan=self.scan)
            current_ports_scans = set(self.storage.get_ports_by_scan_and_node(node=node, scan=self.scan))

            if len(last_scans) < 2:
                previous_ports_scans = set()
            else:
                previous_ports_scans = set(self.storage.get_ports_by_scan_and_node(node=node, scan=last_scans[1]))

            current_ports_scans_dict = {port_scan.port: port_scan for port_scan in current_ports_scans}
            previous_ports_scans_dict = {port_scan.port: port_scan for port_scan in previous_ports_scans}

            current_ports = set(current_ports_scans_dict.keys())
            previous_ports = set(previous_ports_scans_dict.keys())

            new_ports = current_ports - previous_ports
            removed_ports = previous_ports - current_ports

            new_ports_scans = [current_ports_scans_dict[port] for port in new_ports]
            removed_ports_scans = [previous_ports_scans_dict[port] for port in removed_ports]

            changes.extend(PortDetectionChange(change_time=time.time(), previous_finding=None,
                                               current_finding=port_scan) for port_scan in new_ports_scans)

            changes.extend(PortDetectionChange(current_finding=None, change_time=time.time(),
                                               previous_finding=port_scan) for port_scan in removed_ports_scans)

        self.storage.save_changes(changes)
        for change in changes:
            self.aucote.kudu_queue.send_msg(Serializer.serialize_vulnerability_change(change))
