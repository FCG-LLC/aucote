"""
Parsers for Ciscoapis

"""
from tools.ciscoapis.structs import PsirtResult, PsirtResults


class PsirtParser(object):
    """
    Ciscoapi PSIRT output parser. Supports both text and json (default) outputs.

    """
    @classmethod
    def dict_to_result(cls, data: dict) -> PsirtResult:
        """
        Convert ciscoapis result dict to PsirtResult object
        """
        vulnerability = PsirtResult()
        vulnerability.id = data.get('id')
        vulnerability.title = data.get('title')
        vulnerability.bugs = data.get('bugs')
        vulnerability.cves = data.get('cves')
        vulnerability.cvrf = data.get('cvrf')
        vulnerability.oval = data.get('oval')
        vulnerability.cvss = data.get('cvss')
        vulnerability.cwe = data.get('cwe')
        vulnerability.published = data.get('published')
        vulnerability.updated = data.get('updated')
        vulnerability.publication = data.get('publication')
        vulnerability.products = data.get('products')
        vulnerability.sir = data.get('sir')
        vulnerability.summary = data.get('summary')
        return vulnerability

    @classmethod
    def dict_to_results(cls, data: list) -> PsirtResults:
        """
        Convert list of ciscoapis result dicts to PsirtResults
        """
        return_value = PsirtResults()
        return_value.vulnerabilities = tuple(cls.dict_to_result(row) for row in data)
        return return_value
