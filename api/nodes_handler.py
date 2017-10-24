"""
Handler responsible for returning status of aucote

"""
from api.storage_handler import StorageHandler


class NodesHandler(StorageHandler):
    """
    Handler responsible for returning nodes

    """
    LIST_NAME = 'nodes'

    def list(self, limit, page):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
        return {
            'nodes': [self.pretty_node(node_scan) for node_scan in self.aucote.storage.nodes_scans(
                limit, page
            )],
        }

    def details(self, rowid):
        node_scan = self.aucote.storage.node_scan_by_id(rowid)
        if node_scan is None:
            self.set_status(404, 'Node scan not found')
            return {'code': 'Node scan not found'}

        return {
            'id': node_scan.rowid,
            'url': self.url_nodes_scan(node_scan.rowid),
            'node_id': node_scan.node.id,
            'ip': str(node_scan.node.ip),
            'scan': self.pretty_scan(node_scan.scan),
            'scans': [self.pretty_scan(scan) for scan in self.aucote.storage.scans_by_node_scan(node_scan)]
        }
