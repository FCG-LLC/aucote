from api.storage_handler import StorageHandler


class PortsHandler(StorageHandler):
    LIST_NAME = 'ports'

    def list(self, limit, page):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
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
            'url': self.url_ports_scan(port_scan.rowid),
            'timestamp': port_scan.timestamp,
            'port_number': port_scan.port.number,
            'protocol': port_scan.port.transport_protocol.db_val,
            'node_id': port_scan.node.id,
            'node_ip': str(port_scan.node.ip),
            'scan': port_scan.scan.rowid,
            "scan_url": self.url_scan(port_scan.scan.rowid),
            "scans": [self.pretty_scan(scan) for scan in self.aucote.storage.scans_by_port_scan(port_scan)]
        }
