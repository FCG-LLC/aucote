from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.cve_search.structs import CVESearchVulnerabilityResult, CVESearchVulnerabilityResults


class CVESearchVulnerabilityResultTest(TestCase):
    REFERENCES = [
        "http://lists.apple.com/archives/security-announce/2016/Mar/msg00003.html",
        "http://lists.opensuse.org/opensuse-updates/2015-08/msg00022.html",
        "http://rhn.redhat.com/errata/RHSA-2015-1742.html",
        "http://subversion.apache.org/security/CVE-2015-3184-advisory.txt",
        "http://www.debian.org/security/2015/dsa-3331",
        "http://www.securityfocus.com/bid/76274",
        "http://www.securitytracker.com/id/1033215",
        "http://www.ubuntu.com/usn/USN-2721-1",
        "https://support.apple.com/HT206172"
    ]
    ACCESS = {
        "vector": "NETWORK",
        "authentication": "NONE",
        "complexity": "LOW"
    }
    SUMMARY = "mod_authz_svn in Apache Subversion 1.7.x before 1.7.21 and 1.8.x before 1.8.14, when using Apache httpd 2.4.x, does not properly restrict anonymous access, which allows remote anonymous users to read hidden files via the path name."
    MODIFIED = 1482530351430
    VULNERABLE_CONFIGURATION = [
        "cpe:2.3:a:apple:xcode:7.2.1",
        "cpe:2.3:a:apache:subversion:1.7.9",
        "cpe:2.3:a:apache:subversion:1.7.8", "cpe:2.3:a:apache:subversion:1.7.7",
        "cpe:2.3:a:apache:subversion:1.7.6", "cpe:2.3:a:apache:subversion:1.7.5",
        "cpe:2.3:a:apache:subversion:1.7.4", "cpe:2.3:a:apache:subversion:1.7.3",
        "cpe:2.3:a:apache:subversion:1.7.2", "cpe:2.3:a:apache:subversion:1.7.19",
        "cpe:2.3:a:apache:subversion:1.7.18", "cpe:2.3:a:apache:subversion:1.7.17",
        "cpe:2.3:a:apache:subversion:1.7.16", "cpe:2.3:a:apache:subversion:1.7.15",
        "cpe:2.3:a:apache:subversion:1.7.14", "cpe:2.3:a:apache:subversion:1.7.13",
        "cpe:2.3:a:apache:subversion:1.7.12", "cpe:2.3:a:apache:subversion:1.7.11",
        "cpe:2.3:a:apache:subversion:1.7.10", "cpe:2.3:a:apache:subversion:1.7.1",
        "cpe:2.3:a:apache:subversion:1.7.0", "cpe:2.3:a:apache:subversion:1.7.20",
        "cpe:2.3:a:apache:subversion:1.8.9", "cpe:2.3:a:apache:subversion:1.8.8",
        "cpe:2.3:a:apache:subversion:1.8.7", "cpe:2.3:a:apache:subversion:1.8.6",
        "cpe:2.3:a:apache:subversion:1.8.5", "cpe:2.3:a:apache:subversion:1.8.4",
        "cpe:2.3:a:apache:subversion:1.8.3", "cpe:2.3:a:apache:subversion:1.8.2",
        "cpe:2.3:a:apache:subversion:1.8.0", "cpe:2.3:a:apache:subversion:1.8.11",
        "cpe:2.3:a:apache:subversion:1.8.13", "cpe:2.3:a:apache:subversion:1.8.10",
        "cpe:2.3:a:apache:subversion:1.8.1", "cpe:2.3:a:apache:http_server:2.4.1",
        "cpe:2.3:a:apache:http_server:2.4.2", "cpe:2.3:a:apache:http_server:2.4.3",
        "cpe:2.3:a:apache:http_server:2.4.4", "cpe:2.3:a:apache:http_server:2.4.6",
        "cpe:2.3:a:apache:http_server:2.4.7", "cpe:2.3:a:apache:http_server:2.4.9",
        "cpe:2.3:a:apache:http_server:2.4.10", "cpe:2.3:a:apache:http_server:2.4.12",
        "cpe:2.3:a:apache:http_server:2.4.14", "cpe:2.3:a:apache:http_server:2.4.16"
    ]
    IMPACT = {
        "integrity": "NONE",
        "confidentiality": "PARTIAL",
        "availability": "NONE"
    }
    PUBLISHED = 1439377150997,
    VULNERABLE_CONFIGURATION_CPE_2_2 = [
        "cpe:/a:apple:xcode:7.2.1", "cpe:/a:apache:subversion:1.7.9",
        "cpe:/a:apache:subversion:1.7.8", "cpe:/a:apache:subversion:1.7.7",
        "cpe:/a:apache:subversion:1.7.6", "cpe:/a:apache:subversion:1.7.5",
        "cpe:/a:apache:subversion:1.7.4", "cpe:/a:apache:subversion:1.7.3",
        "cpe:/a:apache:subversion:1.7.2", "cpe:/a:apache:subversion:1.7.19",
        "cpe:/a:apache:subversion:1.7.18", "cpe:/a:apache:subversion:1.7.17",
        "cpe:/a:apache:subversion:1.7.16", "cpe:/a:apache:subversion:1.7.15",
        "cpe:/a:apache:subversion:1.7.14", "cpe:/a:apache:subversion:1.7.13",
        "cpe:/a:apache:subversion:1.7.12", "cpe:/a:apache:subversion:1.7.11",
        "cpe:/a:apache:subversion:1.7.10", "cpe:/a:apache:subversion:1.7.1",
        "cpe:/a:apache:subversion:1.7.0", "cpe:/a:apache:subversion:1.7.20",
        "cpe:/a:apache:subversion:1.8.9", "cpe:/a:apache:subversion:1.8.8",
        "cpe:/a:apache:subversion:1.8.7", "cpe:/a:apache:subversion:1.8.6",
        "cpe:/a:apache:subversion:1.8.5", "cpe:/a:apache:subversion:1.8.4",
        "cpe:/a:apache:subversion:1.8.3", "cpe:/a:apache:subversion:1.8.2",
        "cpe:/a:apache:subversion:1.8.0", "cpe:/a:apache:subversion:1.8.11",
        "cpe:/a:apache:subversion:1.8.13", "cpe:/a:apache:subversion:1.8.10",
        "cpe:/a:apache:subversion:1.8.1", "cpe:/a:apache:http_server:2.4.1",
        "cpe:/a:apache:http_server:2.4.2", "cpe:/a:apache:http_server:2.4.3",
        "cpe:/a:apache:http_server:2.4.4", "cpe:/a:apache:http_server:2.4.6",
        "cpe:/a:apache:http_server:2.4.7", "cpe:/a:apache:http_server:2.4.9",
        "cpe:/a:apache:http_server:2.4.10", "cpe:/a:apache:http_server:2.4.12",
        "cpe:/a:apache:http_server:2.4.14", "cpe:/a:apache:http_server:2.4.16"
    ]
    CVSS_TIME = 1459520581440
    CWE = "CWE-200"
    ID = "CVE-2015-3184"
    CVSS = 5.0

    def setUp(self):
        self.result = CVESearchVulnerabilityResult()
        self.result.access = self.ACCESS
        self.result.cvss = self.CVSS
        self.result.cvss_time = self.CVSS_TIME
        self.result.cwe = self.CWE
        self.result.id = self.ID
        self.result.impact = self.IMPACT
        self.result.modified = self.MODIFIED
        self.result.published = self.PUBLISHED
        self.result.references = self.REFERENCES
        self.result.summary = self.SUMMARY
        self.result.vulnerable_configuration = self.VULNERABLE_CONFIGURATION
        self.result.vulnerable_configuration_cpe_2_2 = self.VULNERABLE_CONFIGURATION_CPE_2_2


    def test_result(self):
        expected = """CVE: {cve}
CWE: {cwe}
CVSS: {cvss}

{summary}""".format(cve=self.ID, cwe=self.CWE, cvss=self.CVSS, summary=self.SUMMARY)
        self.assertEqual(self.result.output, expected)


class CVESearchVulnerabilityResultsTest(TestCase):
    def test_output(self):
        results = CVESearchVulnerabilityResults()
        results.vulnerabilities = (MagicMock(output='test_1'), MagicMock(output='test_2'))

        expected = '''test_1

----------
test_2'''

        self.assertEqual(results.output, expected)

    def test_getitem(self):
        results = CVESearchVulnerabilityResults()
        results.vulnerabilities = (MagicMock(output='test_1'), MagicMock(output='test_2'))

        self.assertEqual(results[0], results.vulnerabilities[0])
        self.assertEqual(results[1], results.vulnerabilities[1])
