"""
Handler responsible for returning status of aucote

"""
from api.handler import Handler


class NodesHandler(Handler):
    """
    Handler responsible for returning nodes

    """
    def get(self, node_scan=None):
        if not node_scan:
            self.write(self.nodes_scans())
            return
        self.write(self.node_details(int(node_scan)))

    def nodes_scans(self):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
        return {
            'nodes': [self.pretty_node(node_scan) for node_scan in self.aucote.storage.nodes_scans()],
        }

    def node_details(self, node_scan_id):
        node_scan = self.aucote.storage.node_scan_by_id(node_scan_id)
        if node_scan is None:
            self.set_status(404, "Node scan not found")
            return {"code": "Node scan not found"}

        return {
            "id": node_scan.rowid,
            "url": self.url_nodes_scan(node_scan.rowid),
            "node_id": node_scan.node.id,
            "ip": str(node_scan.node.ip),
            "scan": node_scan.scan.rowid,
            "scan_url": self.url_scan(node_scan.scan.rowid),
            "scans": [self.pretty_scan(scan) for scan in self.aucote.storage.scans_by_node_scan(node_scan)]
        }
