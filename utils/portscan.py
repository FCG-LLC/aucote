from asyncio import ensure_future
from collections import namedtuple
import logging as log

from pycslib.scan_engines import Portscan
from pycslib.scan_engines.portscan import PortscanError
from pycslib.utils.nmap import ports_to_string

from aucote_cfg import cfg
from structs import TransportProtocol, Port
from tools.nmap.tool import NmapTool


class PortscanScanner(object):
    def __init__(self, host, port, io_loop):
        self.portscan = Portscan(host, port, io_loop)
        self.command = namedtuple('command', 'NAME')('portscan')
        ensure_future(self.portscan.connect(), loop=io_loop)

    async def scan_ports(self, nodes):
        include_ports = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.include']).get(TransportProtocol.TCP)
        exclude_ports = NmapTool.ports_from_list(tcp=cfg['portdetection.tcp.ports.exclude']).get(TransportProtocol.TCP)

        ports = list(include_ports - exclude_ports)

        task = {str(node.ip): ports_to_string(set(ports)) for node in nodes}

        try:
            found_ports = await self.portscan.send(task)
        except PortscanError as exception:
            log.error("Error during performing scan: %s", exception)
            found_ports = {}

        return list({
            Port(number=port, node=node, transport_protocol=TransportProtocol.TCP)
            for node in nodes
            for port in found_ports.get(str(node.ip), [])
        })
