class CVESearchVulnerabilityResult(object):

    def __init__(self):
        self.published = None
        self.summary = None
        self.cwe = None
        self.cvss = None
        self.cvss_time = None
        self.id = None
        self.access = None
        self.impact = None
        self.references = None
        self.modified = None
        self.vulnerable_configuration_cpe_2_2 = []
        self.vulnerable_configuration = []

    @property
    def output(self):
        return """CVE: {cve}
CWE: {cwe}
CVSS: {cvss}

{summary}""".format(cve=self.id, cwe=self.cwe, cvss=self.cvss, summary=self.summary)

    @classmethod
    def from_dict(cls, data):
        vulnerability = cls()
        vulnerability.published = list(data.get('Published').values())[0]
        vulnerability.access = data.get('access')
        vulnerability.impact = data.get('impact')
        vulnerability.summary = data.get('summary')
        vulnerability.cwe = data.get('cwe')
        vulnerability.cvss = data.get('cvss')
        vulnerability.cvss_time = list(data.get('cvss-time').values())[0]
        vulnerability.id = data.get('id')
        vulnerability.references = data.get('references')
        vulnerability.modified = list(data.get('Modified').values())[0]
        vulnerability.vulnerable_configuration_cpe_2_2 = data.get('vulnerable_configuration_cpe_2_2')
        vulnerability.vulnerable_configuration = data.get('vulnerable_configuration')
        return vulnerability


class CVESearchVulnerabilityResults(object):
    def __init__(self):
        self.vulnerabilities = []

    @classmethod
    def from_dict(cls, data):
        return_value = cls()
        return_value.vulnerabilities = [CVESearchVulnerabilityResult.from_dict(row) for row in data]
        return return_value

    def __getitem__(self, item):
        return self.vulnerabilities[item]
