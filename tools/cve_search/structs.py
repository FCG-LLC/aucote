"""
CVESearch contains some custom result objects

"""


class CVESearchVulnerabilityResult(object):
    """
    Result of searching cve

    """
    def __init__(self, published=None, summary=None, cwe=None, cvss=None, cvss_time=None, vuln_id=None, access=None,
                 impact=None, references=None, modified=None, vulnerable_configuration_cpe_2_2=None,
                 vulnerable_configuration=None):
        """

        Args:
            published (int):
            summary (str):
            cwe (str):
            cvss (float):
            cvss_time (int):
            vuln_id (str):
            access (dict):
            impact (dict):
            references (list):
            modified (int):
            vulnerable_configuration_cpe_2_2 (list):
            vulnerable_configuration (list):

        """
        self.published = published
        self.summary = summary
        self.cwe = cwe
        self.cvss = cvss
        self.cvss_time = cvss_time
        self.id = vuln_id
        self.access = access
        self.impact = impact
        self.references = references
        self.modified = modified
        self.vulnerable_configuration_cpe_2_2 = vulnerable_configuration_cpe_2_2 or []
        self.vulnerable_configuration = vulnerable_configuration or []

    @property
    def cve(self):
        return self.id

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

{summary}""".format(cve=self.cve, cwe=self.cwe, cvss=self.cvss, summary=self.summary)


class CVESearchVulnerabilityResults(object):
    """
    Contains results of CVE-Search

    """
    def __init__(self, vulnerabilities=None):
        self.vulnerabilities = vulnerabilities or tuple()

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
