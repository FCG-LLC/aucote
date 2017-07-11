from unittest import TestCase
from unittest.mock import patch, MagicMock

from tools.cve_search.parsers import CVESearchParser


class CVESearchParserTest(TestCase):
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
    PARSED_JSON = {
        "references": REFERENCES,
        "access": ACCESS,

        "cvss": CVSS,
        "summary": SUMMARY,
        "Modified": MODIFIED,
        "vulnerable_configuration": VULNERABLE_CONFIGURATION,
        "impact": IMPACT,
        "Published": PUBLISHED,
        "cwe": CWE,
        "id": ID,
        "vulnerable_configuration_cpe_2_2": VULNERABLE_CONFIGURATION_CPE_2_2,
        "cvss-time": CVSS_TIME
    }

    def test_dict_to_result(self):
        result = CVESearchParser.dict_to_result(self.PARSED_JSON)

        self.assertEqual(result.access, self.ACCESS)
        self.assertEqual(result.cvss, self.CVSS)
        self.assertEqual(result.cvss_time, self.CVSS_TIME)
        self.assertEqual(result.cwe, self.CWE)
        self.assertEqual(result.id, self.ID)
        self.assertEqual(result.impact, self.IMPACT)
        self.assertEqual(result.modified, self.MODIFIED)
        self.assertEqual(result.published, self.PUBLISHED)
        self.assertEqual(result.references, self.REFERENCES)
        self.assertEqual(result.summary, self.SUMMARY)
        self.assertEqual(result.vulnerable_configuration, self.VULNERABLE_CONFIGURATION)
        self.assertEqual(result.vulnerable_configuration_cpe_2_2, self.VULNERABLE_CONFIGURATION_CPE_2_2)

    @patch('tools.cve_search.parsers.CVESearchParser.dict_to_result')
    def test_dict_to_results(self, mock_result):
        data = [1, 2]
        expected = [MagicMock(), MagicMock()]
        mock_result.side_effect = expected
        results = CVESearchParser.dict_to_results(data=data)

        self.assertEqual(results.vulnerabilities, expected)
