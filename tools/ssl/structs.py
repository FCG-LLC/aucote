"""
Structures for integration with testssl
"""
from enum import Enum


class SSLSeverity(Enum):
    """
    Severity used by testssl

    """
    def __init__(self, text, score):
        self.text = text
        self.score = score

    OK = ("OK", 0)
    DEBUG = ("DEBUG", 0)
    INFO = ("INFO", 0)
    NOT_OK = ("NOT OK", 1)
    LOW = ("LOW", 1)
    MINOR = ("MINOR", 1)
    MEDIUM = ("MEDIUM", 2)
    WARN = ("WARN", 2)
    HIGH = ("HIGH", 3)
    ERROR = ("ERROR", 3)
    CRITICAL = ("CRITICAL", 4)

    @classmethod
    def from_name(cls, text):
        """
        Returns SSLSeverity basing on text

        Args:
            text:

        Returns:
            SSLSeverity

        """
        text = text.upper()
        for val in cls:
            if val.text == text:
                return val
        raise ValueError('Invalid testssl severity name: %s' % text)


class SSLResult(object):
    """
    Single result of testssl checks

    """
    def __init__(self, json):
        self.id = json.get('id')
        self.ip = json.get('ip')
        self.port = json.get('port')
        self.severity = SSLSeverity.from_name(json.get('severity'))
        self.cve = json.get('cve')
        self.cwe = json.get('cwe')
        self.finding = json.get('finding')

    @property
    def output(self):
        """
        Pretty output of result

        Returns:
            str

        """
        return """CVE: {cve}
Finding: {finding}""".format(cve=self.cve, finding=self.finding)


class SSLResults(object):
    """
    Contains set of SSLResult objects. Provides interface for managing them.

    """
    def __init__(self, json=None):
        self.results = None
        if json:
            self.results = [SSLResult(single_json) for single_json in json]

    def with_severity_ge(self, severity):
        """
        Get all results for which severity is greater or equal than given

        Args:
            severity (SSLSeverity):

        Returns:
            SSLResults

        """
        return_value = SSLResults
        return_value.results = [result for result in self.results if result.severity.score >= severity.score]

        return return_value

    @property
    def output(self):
        """
        Pretty output of results

        Returns:
            str

        """
        return "\n\n----------\n\n".join([result.output for result in self.results])
