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

    def scan_history(self, scan_id):
        scan = self.aucote.storage.get_scan_by_id(scan_id)
        return {
            "scan": scan_id,
            "url": self.url_scan(scan_id),
            "nodes": [self.pretty_node(nodes_scans) for nodes_scans in self.aucote.storage.nodes_scans_by_scan(scan)],
            "ports": [self.pretty_port(port_scan) for port_scan in self.aucote.storage.ports_scans_by_scan(scan)]
        }
