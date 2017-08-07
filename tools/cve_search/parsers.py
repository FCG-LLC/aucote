"""
Parsers for CVE-search tool

"""
from tools.cve_search.structs import CVESearchVulnerabilityResult, CVESearchVulnerabilityResults


class CVESearchParser(object):
    """
    CVE-search output parser. Supports both text and json (default) outputs.

    """
    @classmethod
    def dict_to_result(cls, data):
        """
        Convert cve-search result dict to CVESearchVulnerabilityResult object

        Args:
            data (dict):

        Returns:
            CVESearchVulnerabilityResult

        """
        vulnerability = CVESearchVulnerabilityResult()
        vulnerability.published = data.get('Published')
        vulnerability.access = data.get('access')
        vulnerability.impact = data.get('impact')
        vulnerability.summary = data.get('summary')
        vulnerability.cwe = data.get('cwe')
        vulnerability.cvss = data.get('cvss')
        vulnerability.cvss_time = data.get('cvss-time')
        vulnerability.id = data.get('id')
        vulnerability.references = data.get('references')
        vulnerability.modified = data.get('Modified')
        vulnerability.vulnerable_configuration_cpe_2_2 = data.get('vulnerable_configuration_cpe_2_2')
        vulnerability.vulnerable_configuration = data.get('vulnerable_configuration')
        return vulnerability

    @classmethod
    def dict_to_results(cls, data):
        """
        Convert list of cve-search result dicts to CVESearchVulnerabilityResults object

        Args:
            data (list):

        Returns:
            CVESearchVulnerabilityResults

        """
        return_value = CVESearchVulnerabilityResults()
        return_value.vulnerabilities = tuple(cls.dict_to_result(row) for row in data)
        return return_value
