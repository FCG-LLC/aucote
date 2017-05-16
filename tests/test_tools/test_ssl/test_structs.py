from unittest import TestCase

from tools.ssl.structs import SSLSeverity, SSLResult, SSLResults


class SSLSeverityTest(TestCase):
    def test_from_name(self):
        self.assertEqual(SSLSeverity.from_name('info'), SSLSeverity.INFO)
        self.assertEqual(SSLSeverity.from_name('critical'), SSLSeverity.CRITICAL)

    def test_from_name_doesnt_exist(self):
        self.assertRaises(ValueError, SSLSeverity.from_name, 'test')


class SSLResultTest(TestCase):
    RESULT_DICT = {
        "id": "heartbleed",
        "ip": "10.12.1.24/10.12.1.24",
        "port": "443",
        "severity": "OK",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-119",
        "finding": "Heartbleed: not vulnerable , timed out"
    }

    LESS_INFORMATIVE_RESULT = {
        "id": "service",
        "ip": "10.12.1.24/10.12.1.24",
        "port": "443",
        "severity": "INFO",
        "finding": "Service detected: HTTP"
    }

    def setUp(self):
        self.result = SSLResult(self.RESULT_DICT)

    def test_init(self):
        self.assertEqual(self.result.id, "heartbleed")
        self.assertEqual(self.result.ip, "10.12.1.24/10.12.1.24")
        self.assertEqual(self.result.port, "443")
        self.assertEqual(self.result.cve, "CVE-2014-0160")
        self.assertEqual(self.result.cwe, "CWE-119")
        self.assertEqual(self.result.finding, "Heartbleed: not vulnerable , timed out")
        self.assertEqual(self.result.severity, SSLSeverity.OK)

    def test_less_informative_result(self):
        result = SSLResult(self.LESS_INFORMATIVE_RESULT)
        self.assertEqual(result.id, "service")
        self.assertEqual(result.ip, "10.12.1.24/10.12.1.24")
        self.assertEqual(result.port, "443")
        self.assertEqual(result.cve, None)
        self.assertEqual(result.cwe, None)
        self.assertEqual(result.finding, "Service detected: HTTP")
        self.assertEqual(result.severity, SSLSeverity.INFO)

    def test_output(self):
        expected = """CVE: CVE-2014-0160
Finding: Heartbleed: not vulnerable , timed out"""
        result = self.result.output

        self.assertEqual(result, expected)


class SSLResultsTest(TestCase):
    RESULT_DICT = [
        {
            "id": "heartbleed",
            "ip": "10.12.1.24/10.12.1.24",
            "port": "443",
            "severity": "OK",
            "cve": "CVE-2014-0160",
            "cwe": "CWE-119",
            "finding": "Heartbleed: not vulnerable , timed out"
        }
    ]

    OK_RESULT = {
        "id": "heartbleed",
        "ip": "10.12.1.24/10.12.1.24",
        "port": "443",
        "severity": "OK",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-119",
        "finding": "Heartbleed: not vulnerable , timed out"
    }

    INFO_RESULT = {
        "id": "heartbleed",
        "ip": "10.12.1.24/10.12.1.24",
        "port": "443",
        "severity": "INFO",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-119",
        "finding": "Heartbleed: not vulnerable , timed out"
    }

    MEDIUM_RESULT = {
        "id": "heartbleed",
        "ip": "10.12.1.24/10.12.1.24",
        "port": "443",
        "severity": "MEDIUM",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-119",
        "finding": "Heartbleed: not vulnerable , timed out"
    }

    CRITICAL_RESULT = {
        "id": "heartbleed",
        "ip": "10.12.1.24/10.12.1.24",
        "port": "443",
        "severity": "CRITICAL",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-119",
        "finding": "Heartbleed: not vulnerable , timed out"
    }

    def setUp(self):
        self.results = SSLResults(self.RESULT_DICT)
        self.result_ok = SSLResult(self.OK_RESULT)
        self.result_info = SSLResult(self.INFO_RESULT)
        self.result_medium = SSLResult(self.MEDIUM_RESULT)
        self.result_critical = SSLResult(self.CRITICAL_RESULT)

    def test_init(self):
        self.assertEqual(len(self.results.results), 1)
        self.assertEqual(self.results.results[0].severity, SSLSeverity.OK)
        self.assertEqual(self.results.results[0].id, "heartbleed")

    def test_with_severity(self):
        self.results.results = [self.result_info, self.result_critical, self.result_ok, self.result_medium]

        result = self.results.with_severity_ge(SSLSeverity.MEDIUM)
        expected = [self.result_medium, self.result_critical]

        self.assertCountEqual(result.results, expected)

    def test_output(self):
        self.results.results = [self.result_critical, self.result_medium]
        expected = """CVE: CVE-2014-0160
Finding: Heartbleed: not vulnerable , timed out

----------

CVE: CVE-2014-0160
Finding: Heartbleed: not vulnerable , timed out"""
        result = self.results.output

        self.assertEqual(result, expected)
