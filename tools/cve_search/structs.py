"""
CVESearch contains some custom result objects

"""


class CVESearchVulnerabilityResult(object):
    """
    Result of searching cve

    """
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
        """
        CVE-Search output in human readable form

        Returns:
            str

        """
        return """CVE: {cve}
CWE: {cwe}
CVSS: {cvss}

{summary}""".format(cve=self.id, cwe=self.cwe, cvss=self.cvss, summary=self.summary)


class CVESearchVulnerabilityResults(object):
    """
    Contains results of CVE-Search

    """
    def __init__(self):
        self.vulnerabilities = []

    def __getitem__(self, item):
        return self.vulnerabilities[item]

    @property
    def output(self):
        """
        CVE-Search output in human readable form

        Returns:
            str

        """
        return '\n\n----------\n'.join([vuln.output for vuln in self.vulnerabilities])
