"""
Handler responsible for returning status of aucote

"""
from api.storage_handler import StorageHandler
from utils.time import parse_timestamp_to_time


class ScansHandler(StorageHandler):
    """
    Handler responsible for returning status of aucote

    """
    LIST_NAME = 'scans'

    def list(self, limit, page):
        """
        Get current status of aucote tasks

        Returns:
            dict

        """
        return {
            'scans': [self.pretty_scan(scan) for scan in self.aucote.storage.scans(limit, page)],
        }

    def details(self, rowid):
        scan = self.aucote.storage.get_scan_by_id(rowid)
        return {
            "scan": rowid,
            "url": self.url_scan(rowid),
            "start": scan.start,
            "start_human": parse_timestamp_to_time(scan.start),
            "end": scan.end,
            "end_human": parse_timestamp_to_time(scan.end),
            "nodes_scans": [self.pretty_node(nodes_scans)
                            for nodes_scans in self.aucote.storage.nodes_scans_by_scan(scan)],
            "ports_scans": [self.pretty_port_scan(port_scan)
                            for port_scan in self.aucote.storage.ports_scans_by_scan(scan)]
        }
