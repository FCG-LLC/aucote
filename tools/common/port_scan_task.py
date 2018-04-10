"""
Base class for scanners

"""
import logging as log

from tornado import gen

from aucote_cfg import cfg
from tools.common import OpenPortsParser
from utils.exceptions import NonXMLOutputException, StopCommandException


class PortScanTask(object):
    """
    Base class for scanner

    """

    def __init__(self, command, tcp=True, udp=True):
        self.command = command
        self.tcp = tcp
        self.udp = udp

    async def prepare_args(self, nodes):
        """
        Prepare args for command execution

        Args:
            nodes (list): nodes from scanning

        Returns:
            list

        """
        raise NotImplementedError

    async def scan_ports(self, nodes):
        """
        Scan nodes for open ports. If ports are passed, scans only them. Returns list of open ports.

        Args:
            nodes (list):
            ports (list):

        Returns:
            list

        """
        if not nodes:
            return []

        try:
            args = await self.prepare_args(nodes)
        except StopCommandException as exception:
            log.warning("Cannot execute command: %s", str(exception))
            return []

        try:
            xml = await self.command.async_call(args, timeout=0)
        except NonXMLOutputException:
            return []
        except gen.TimeoutError:
            return []

        node_by_ip = {node.ip: node for node in nodes}
        ports = OpenPortsParser.parse(xml, node_by_ip)
        return ports

    def kill(self):
        if self.command:
            self.command.kill()

    def scan_rate(self):
        base_rate = cfg['portdetection.tcp.scan_rate'] if self.tcp else cfg['portdetection.udp.scan_rate']
        throttling = cfg.toucan.get('throttling.rate', add_prefix=False) if cfg.toucan is not None else 1

        if throttling > 1:
            throttling = 1

        if throttling < 0:
            throttling = 0

        rate = str(int(float(throttling) * int(base_rate)))

        if rate == '0':
            raise StopCommandException("Cancel scan due to low throttling rate {}".format(throttling))

        return rate
