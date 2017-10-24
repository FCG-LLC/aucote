from api.storage_handler import StorageHandler
from utils.time import parse_timestamp_to_time


class VulnerabilitiesHandler(StorageHandler):
    LIST_NAME = 'vulnerabilities'

    def list(self, limit, page):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
        return {
            'vulnerabilitites': [self.pretty_vulnerability(vuln) for vuln in self.aucote.storage.vulnerabilities(
                limit, page
            )],
        }

    def pretty_vulnerability(self, vulnerability):
        return {
            'id': vulnerability.rowid,
            'url': self._url_vulnerability(vulnerability.rowid),
            'port': str(vulnerability.port),
            'scan': self.pretty_scan(vulnerability.scan),
            'output': vulnerability.output[:100],
            'exploit': vulnerability.exploit.id,
            'vuln_subid': vulnerability.subid,
            'time': vulnerability.time,
            'time_human': parse_timestamp_to_time(vulnerability.time),
            'cvss': vulnerability.cvss
        }

    def details(self, rowid):
        vulnerability = self.aucote.storage.vulnerability_by_id(rowid)
        if vulnerability is None:
            self.set_status(404, 'Vulnerability not found')
            return {"code": "Vulnerability not found"}

        return {
            'id': vulnerability.rowid,
            'url': self._url_security_scan(vulnerability.rowid),
            'port': self.pretty_port(vulnerability.port),
            'scan': self.pretty_scan(vulnerability.scan),
            'time': vulnerability.time,
            'time_human': parse_timestamp_to_time(vulnerability.time),
            'exploit': vulnerability.exploit.id,
            'output': vulnerability.output,
            'scans': [self.pretty_scan(scan)
                      for scan in self.aucote.storage.scans_by_vulnerability(vulnerability)]
        }
