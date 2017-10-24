"""
Handler responsible for returning aucote's ports

"""
from api.storage_handler import StorageHandler
from utils.time import parse_timestamp_to_time


class PortsHandler(StorageHandler):
    LIST_NAME = 'ports'

    def list(self, limit, page):
        return {
            'ports': [self.pretty_port_scan(port_scan) for port_scan in self.aucote.storage.ports_scans(
                limit, page
            )],
        }

    def details(self, rowid):
        port_scan = self.aucote.storage.port_scan_by_id(rowid)
        if port_scan is None:
            self.set_status(404, 'Port scan not found')
            return {"code": "Port scan not found"}

        return {
            'id': port_scan.rowid,
            'url': self._url_ports_scan(port_scan.rowid),
            'timestamp': port_scan.timestamp,
            'human_timestamp': parse_timestamp_to_time(port_scan.timestamp),
            'port_number': port_scan.port.number,
            'protocol': port_scan.port.transport_protocol.db_val,
            'node': {
                'id': port_scan.node.id,
                'ip': str(port_scan.node.ip)
            },
            'scan': self.pretty_scan(port_scan.scan),
            'scans': [self.pretty_scan(scan) for scan in self.aucote.storage.scans_by_port_scan(port_scan)]
        }
