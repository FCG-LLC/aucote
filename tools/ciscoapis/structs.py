"""
CVESearch contains some custom result objects

"""
from typing import List


class PsirtResult:
    """
    Result of searching cve

    """
    def __init__(self, id: str = None, title: str = None, bugs: List[str] = None, signatures: List[str] = None,
                 cves: List[str] = None, cvrf: str = None, oval: List[str] = None, cvss: float = None,
                 cwe: List[str] = None, published: int = None, updated: int = None, products: List[str] = None,
                 publication: str = None, sir: str = None, summary: str = None):
        self.id = id
        self.title = title
        self.bugs = bugs if bugs is not None else []
        self.cves = cves if cves is not None else []
        self.cvrf = cvrf
        self.oval = oval if oval is not None else []
        self.cvss = cvss
        self.cwe = cwe if cwe is not None else []
        self.published = published
        self.updated = updated
        self.publication = publication
        self.products = products if products is not None else []
        self.sir = sir
        self.summary = summary

    @property
    def cve(self) -> str:
        return ', '.join(self.cves)

    @property
    def output(self) -> str:
        return self.summary


class PsirtResults(object):
    """
    Contains results of ciscoapis/PSIRT

    """
    def __init__(self, vulnerabilities: [list, tuple] = None):
        self.vulnerabilities = vulnerabilities or tuple()

    def __getitem__(self, item: int) -> PsirtResult:
        return self.vulnerabilities[item]

    @property
    def output(self) -> str:
        """
        ciscoapis/PSIRT output in human readable form
        """
        return '\n\n----------\n'.join([vuln.output for vuln in self.vulnerabilities])
