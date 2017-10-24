from api.storage_handler import StorageHandler
from utils.time import parse_timestamp_to_time


class SecurityScansHandler(StorageHandler):
    LIST_NAME = 'security_scans'

    def list(self, limit, page):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
        return {
            'security_scans': [self.pretty_sec_scan(sec_scan) for sec_scan in self.aucote.storage.security_scans(
                limit, page
            )],
        }

    def pretty_sec_scan(self, sec_scan):
        return {
            'id': sec_scan.rowid,
            'url': self.url_security_scan(sec_scan.rowid),
            'port': self.pretty_port(sec_scan.port),
            'scan': self.pretty_scan(sec_scan.scan),
            'scan_end': sec_scan.scan_end,
            'scan_end_human': parse_timestamp_to_time(sec_scan.scan_end),
            'scan_start': sec_scan.scan_start,
            'scan_start_human': parse_timestamp_to_time(sec_scan.scan_start),
            'exploit': {
                'id': sec_scan.exploit.id,
                'app': sec_scan.exploit.app,
                'name': sec_scan.exploit.name
            }
        }

    def details(self, rowid):
        sec_scan = self.aucote.storage.security_scan_by_id(rowid)
        if sec_scan is None:
            self.set_status(404, 'Security scan not found')
            return {'code': 'Security scan not found'}

        return {
            'id': sec_scan.rowid,
            'url': self.url_security_scan(sec_scan.rowid),
            'port': self.pretty_port(sec_scan.port),
            'scan': self.pretty_scan(sec_scan.scan),
            'scan_end': sec_scan.scan_end,
            'scan_end_human': parse_timestamp_to_time(sec_scan.scan_end),
            'scan_start': sec_scan.scan_start,
            'scan_start_human': parse_timestamp_to_time(sec_scan.scan_start),
            'exploit': {
                'id': sec_scan.exploit.id,
                'app': sec_scan.exploit.app,
                'name': sec_scan.exploit.name
            },
            'scan_url': self.url_scan(sec_scan.scan.rowid),
            'scans': [self.pretty_scan(scan)
                      for scan in self.aucote.storage.scans_by_security_scan(sec_scan)]
        }
