from api.handler import Handler


class PortsHandler(Handler):
    def get(self, port_scan=None):
        if not port_scan:
            self.write(self.ports_scans())
            return
        self.write(self.ports_details(int(port_scan)))

    def ports_scans(self):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
        return {
            'ports': [self.pretty_port_scan(port_scan) for port_scan in self.aucote.storage.ports_scans()],
        }

    def ports_details(self, port_scan_id):
        port_scan = self.aucote.storage.port_scan_by_id(port_scan_id)
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
