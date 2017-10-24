"""
Handler responsible for returning aucote's scanners

"""
from api.storage_handler import StorageHandler
from scans.tools_scanner import ToolsScanner


class ScannersHandler(StorageHandler):
    def get(self, scan=None):
        """
        Handle get method and returns aucote status in JSON

        Returns:
            None - writes aucote status in JSON

        """
        if not scan:
            self.write(self.scans())
            return
        self.write(self.scan_status(scan))

    def scan_status(self, scan):
        """
        Get current status of aucote tasks

        Returns:
            dict

        """
        scanner = self.get_scanner(name=scan)
        if not scanner:
            self.set_status(404, 'Scan not found')
            return {'code': 'Scan not found'}

        if isinstance(scanner, ToolsScanner):
            self.set_status(500, 'Security scans are unsupported right now')
            return {'code': 'Security scans are unsupported right now'}

        stats = {
            'scan': scan,
            'current_scan': scanner.scan_start,
            'previous_scan': scanner.previous_scan,
            'next_scan': scanner.next_scan,
            'scanners': {protocol: [subscanner.command.NAME for subscanner in subscanners]
                         for protocol, subscanners in scanner.scanners.items()},
            'status': scanner.status.value if scanner.status is not None else None,
            'nodes': [str(node) for node in scanner.nodes]
        }
        return stats

    def get_scanner(self, name):
        for scanner in self.aucote.scanners:
            if scanner.NAME == name:
                return scanner

        return None

    def scans(self):
        """
        Get current status of aucote tasks

        Returns:
            dict

        """
        return {
            'scanners': [self.pretty_scanner(scanner) for scanner in self.aucote.scanners],
        }

    def pretty_scanner(self, scanner):
        return {
            'name': scanner.NAME,
            'url': self._url_scanner(scanner.NAME)
        }
