import copy
from unittest import TestCase

from tools.ssl.structs import SSLSeverity, SSLResult, SSLResults


class SSLSeverityTest(TestCase):
    def test_from_name(self):
        self.assertEqual(SSLSeverity.from_name('info'), SSLSeverity.INFO)
        self.assertEqual(SSLSeverity.from_name('critical'), SSLSeverity.CRITICAL)

    def test_from_name_doesnt_exist(self):
        self.assertRaises(ValueError, SSLSeverity.from_name, 'test')


class SSLResultTest(TestCase):
    RESULT = SSLResult()
    RESULT.id = "heartbleed"
    RESULT.ip = "10.12.1.24/10.12.1.24"
    RESULT.port = "443"
    RESULT.severity = SSLSeverity.OK
    RESULT.cve = "CVE-2014-0160"
    RESULT.cwe = "CWE-119"
    RESULT.finding = "Heartbleed: not vulnerable , timed out"
    

    LESS_INFORMATIVE_RESULT = SSLResult()
    LESS_INFORMATIVE_RESULT.id = "service"
    LESS_INFORMATIVE_RESULT.ip = "10.12.1.24/10.12.1.24"
    LESS_INFORMATIVE_RESULT.port = "443"
    LESS_INFORMATIVE_RESULT.severity = SSLSeverity.INFO
    LESS_INFORMATIVE_RESULT.finding = "Service detected: HTTP"

    def test_init(self):
        self.assertEqual(self.RESULT.id, "heartbleed")
        self.assertEqual(self.RESULT.ip, "10.12.1.24/10.12.1.24")
        self.assertEqual(self.RESULT.port, "443")
        self.assertEqual(self.RESULT.cve, "CVE-2014-0160")
        self.assertEqual(self.RESULT.cwe, "CWE-119")
        self.assertEqual(self.RESULT.finding, "Heartbleed: not vulnerable , timed out")
        self.assertEqual(self.RESULT.severity, SSLSeverity.OK)

    def test_less_informative_result(self):
        result = self.LESS_INFORMATIVE_RESULT
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
        result = self.RESULT.output

        self.assertEqual(result, expected)


class SSLResultsTest(TestCase):
    RESULT = SSLResult()
    RESULT.id = "heartbleed"
    RESULT.ip = "10.12.1.24/10.12.1.24"
    RESULT.port = "443"
    RESULT.severity = SSLSeverity.OK
    RESULT.cve = "CVE-2014-0160"
    RESULT.cwe = "CWE-119"
    RESULT.finding = "Heartbleed: not vulnerable , timed out"

    OK_RESULT = SSLResult()
    OK_RESULT.severity = SSLSeverity.OK
    INFO_RESULT = SSLResult()
    INFO_RESULT.severity = SSLSeverity.INFO

    MEDIUM_RESULT = SSLResult()
    MEDIUM_RESULT.severity = SSLSeverity.MEDIUM
    MEDIUM_RESULT.finding = "Heartbleed: not vulnerable , timed out"

    CRITICAL_RESULT = SSLResult()
    CRITICAL_RESULT.severity = SSLSeverity.CRITICAL
    CRITICAL_RESULT.finding = "Heartbleed: not vulnerable , timed out"
    CRITICAL_RESULT.cve = "CVE-2014-0160"

    RESULTS = SSLResults()
    RESULTS.results.append(RESULT)

    def test_init(self):
        self.assertEqual(len(self.RESULTS.results), 1)
        self.assertEqual(self.RESULTS.results[0].severity, SSLSeverity.OK)
        self.assertEqual(self.RESULTS.results[0].id, "heartbleed")

    def test_with_severity_ge(self):
        self.RESULTS.results = [self.INFO_RESULT, self.CRITICAL_RESULT, self.OK_RESULT, self.MEDIUM_RESULT]

        result = self.RESULTS.with_severity_ge(SSLSeverity.MEDIUM)
        expected = [self.MEDIUM_RESULT, self.CRITICAL_RESULT]

        self.assertCountEqual(result.results, expected)

    def test_with_severity_le(self):
        self.RESULTS.results = [self.INFO_RESULT, self.CRITICAL_RESULT, self.OK_RESULT, self.MEDIUM_RESULT]

        result = self.RESULTS.with_severity_le(SSLSeverity.MEDIUM)
        expected = [self.MEDIUM_RESULT, self.OK_RESULT, self.INFO_RESULT]

        self.assertCountEqual(result.results, expected)

    def test_output(self):
        self.RESULTS.results = [self.CRITICAL_RESULT, self.MEDIUM_RESULT]
        expected = """CVE: CVE-2014-0160
Finding: Heartbleed: not vulnerable , timed out
Heartbleed: not vulnerable , timed out"""
        result = self.RESULTS.output

        self.assertEqual(result, expected)
