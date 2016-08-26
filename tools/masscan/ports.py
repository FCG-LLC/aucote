from utils.exceptions import NonXMLOutputException
from .base import MasscanBase
from ..common import OpenPortsParser
from aucote_cfg import cfg

class MasscanPorts(MasscanBase):
    '''
    Scans for open ports using masscan application
    '''

    def scan_ports(self, nodes):
        args = ['--rate', str(cfg.get('service.scans.rate')),
                '--ports', str(cfg.get('service.scans.ports'))]

        args.extend(cfg.get('tools.masscan.args').cfg)

        args.extend([str(node.ip) for node in nodes])
        try:
            xml = self.call(args)
        except NonXMLOutputException:
            return []
        parser = OpenPortsParser()
        node_by_ip = {node.ip: node for node in nodes}
        ports = parser.parse(xml, node_by_ip)
        return ports
