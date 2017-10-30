"""
Handler responsible for returning aucote's scanners

"""
from api.storage_handler import StorageHandler
from scans.tools_scanner import ToolsScanner
from utils.time import parse_timestamp_to_time


class ScannersHandler(StorageHandler):
    def get(self, scan=None):
        """
        Handle get method and returns scanners information

        Returns:
            None - writes aucote status in JSON

        """
        if not scan:
            self.write(self.scanners())
            return
        self.write(self.scanner_status(scan))

    def scanner_status(self, scan):
        """
        Get scanner status

        """
        scanner = self.get_scanner(name=scan)
        if not scanner:
            return self.not_found('Scanner not found')

        if isinstance(scanner, ToolsScanner):
            return self.internal_error('Security scanners are not implemented right now')

        stats = {
            'scan': scan,
            'current_scan': scanner.scan_start,
            'current_scan_human': parse_timestamp_to_time(scanner.scan_start),
            'previous_scan': scanner.previous_scan,
            'previous_scan_human': parse_timestamp_to_time(scanner.previous_scan),
            'next_scan': scanner.next_scan,
            'next_scan_human': parse_timestamp_to_time(scanner.next_scan),
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

    def scanners(self):
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
