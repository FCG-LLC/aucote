from api.handler import Handler


class VulnerabilitiesHandler(Handler):
    def get(self, vulnerability=None):
        if not vulnerability:
            self.write(self.vulnerabilitites())
            return
        self.write(self.vulnerability_details(int(vulnerability)))

    def vulnerabilitites(self):
        """
        Get current status of aucote nodes

        Returns:
            dict

        """
        return {
            'vulnerabilitites': [self.pretty_vulnerability(vuln) for vuln in self.aucote.storage.vulnerabilities()],
        }

    def pretty_vulnerability(self, vulnerability):
        return {
            'id': vulnerability.rowid,
            'url': self.url_vulnerability(vulnerability.rowid),
            'port': str(vulnerability.port),
            'scan': self.pretty_scan(vulnerability.scan),
            'output': vulnerability.output[:100],
            'exploit': vulnerability.exploit.id,
            'vuln_subid': vulnerability.subid,
            'time': vulnerability.time,
            'cvss': vulnerability.cvss
        }

    def vulnerability_details(self, vuln_id):
        vulnerability = self.aucote.storage.vulnerability_by_id(vuln_id)
        if vulnerability is None:
            self.set_status(404, 'Vulnerability not found')
            return {"code": "Vulnerability not found"}

        return {
            'id': vulnerability.rowid,
            'url': self.url_security_scan(vulnerability.rowid),
            'port': self.pretty_port(vulnerability.port),
            'scan': self.pretty_scan(vulnerability.scan),
            'time': vulnerability.time,
            'exploit': vulnerability.exploit.id,
            'output': vulnerability.output,
            "scans": [self.pretty_scan(scan)
                      for scan in self.aucote.storage.scans_by_vulnerability(vulnerability)]
        }
