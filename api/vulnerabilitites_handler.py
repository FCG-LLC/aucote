"""
Handler responsible for returning aucote's vulnerabilities

"""
from api.storage_handler import StorageHandler
from utils.time import parse_timestamp_to_time


class VulnerabilitiesHandler(StorageHandler):
    ENDPOINT_NAME = 'vulnerabilities'

    def list(self, limit, page):
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
            'cvss': vulnerability.cvss,
        }

    def details(self, rowid):
        vulnerability = self.aucote.storage.vulnerability_by_id(rowid)

        return self.not_found('Vulnerability not found') if vulnerability is None else {
            'id': vulnerability.rowid,
            'url': self._url_vulnerability(vulnerability.rowid),
            'port': self.pretty_port(vulnerability.port),
            'scan': self.pretty_scan(vulnerability.scan),
            'time': vulnerability.time,
            'time_human': parse_timestamp_to_time(vulnerability.time),
            'exploit': vulnerability.exploit.id,
            'output': vulnerability.output,
            'expired': vulnerability.expiration_time,
            'expired_human': parse_timestamp_to_time(vulnerability.expiration_time),
            'scans': [self.pretty_scan(scan)
                      for scan in self.aucote.storage.scans_by_vulnerability(vulnerability)]
        }
