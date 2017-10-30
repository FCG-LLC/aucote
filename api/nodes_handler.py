"""
Handler responsible for returning aucote's nodes

"""
from api.storage_handler import StorageHandler


class NodesHandler(StorageHandler):
    ENDPOINT_NAME = 'nodes'

    def list(self, limit, page):
        return {
            'nodes': [self.pretty_node(node_scan) for node_scan in self.aucote.storage.nodes_scans(
                limit, page
            )],
        }

    def details(self, rowid):
        node_scan = self.aucote.storage.node_scan_by_id(rowid)

        return self.not_found('Node scan not found') if node_scan is None else {
            'id': node_scan.rowid,
            'url': self._url_nodes_scan(node_scan.rowid),
            'node_id': node_scan.node.id,
            'ip': str(node_scan.node.ip),
            'scan': self.pretty_scan(node_scan.scan),
            'scans': [self.pretty_scan(scan) for scan in self.aucote.storage.scans_by_node_scan(node_scan)]
        }
