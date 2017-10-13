"""
Handler responsible for returning status of aucote

"""
from api.handler import Handler


class ScansHandler(Handler):
    """
    Handler responsible for returning status of aucote

    """
    def get(self, scan=None):
        """
        Handle get method and returns aucote status in JSON

        Returns:
            None - writes aucote status in JSON

        """
        if not scan:
            self.write(self.scans())
            return
        self.write(self.scan_history(int(scan)))

    def scans(self):
        """
        Get current status of aucote tasks

        Returns:
            dict

        """
        return {
            'scans': [self.pretty_scan(scan) for scan in self.aucote.storage.scans()],
        }

    def pretty_scan(self, scan):
        """

        Args:
            scan (Scan):

        Returns:

        """
        return {
            "id": scan.rowid,
            "url": self.url_scan(scan.rowid),
            "start": scan.start,
            "end": scan.end,
            "protocol": scan.protocol.db_val if scan.protocol else None,
            "scanner": scan._scanner,
            "scanner_url": self.url_scanner(scan._scanner)
        }

    def scan_history(self, scan_id):
        scan = self.aucote.storage.get_scan_by_id(scan_id)
        return {
            "scan": scan_id,
            "url": self.url_scan(scan_id),
            "nodes": [str(node) for node in self.aucote.storage.get_nodes_by_scan(scan)],
            "ports": [str(port_scan.port) for port_scan in self.aucote.storage.get_ports_scans_by_scan(scan)]
        }
