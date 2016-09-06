from unittest import TestCase
from unittest.mock import MagicMock

from tools.skipfish.structs import SkipfishIssuesDesc, SkipfishIssueSample, SkipfishIssues, SkipfishRisk


class SkipfishIssuesDescTest(TestCase):
    def setUp(self):
        self.issues = SkipfishIssuesDesc()

    def test_add(self):
        data = {"10101": "SSL certificate issuer information"}
        self.issues.add(data)
        result = self.issues._issues["10101"]
        expected = "SSL certificate issuer information"

        self.assertEqual(result, expected)

    def test_get(self):
        data = "SSL certificate issuer information"
        self.issues._issues["10101"] = data
        result = self.issues["10101"]
        expected = "SSL certificate issuer information"

        self.assertEqual(result, expected)

    def test_int_get(self):
        data = "SSL certificate issuer information"
        self.issues._issues["10101"] = data
        result = self.issues[10101]
        expected = "SSL certificate issuer information"

        self.assertEqual(result, expected)


class SkipfishIssueSampleTest(TestCase):

    severity = SkipfishRisk.NOTE
    severity_type = MagicMock()
    url = 'test_url'
    extra = 'test_extra'
    sid = 'test_sid'
    dir = 'test_dir'

    def setUp(self):
        self.samples = SkipfishIssueSample(severity=self.severity, severity_type=self.severity_type, url=self.url,
                                           extra=self.extra, sid=self.sid, directory=self.dir)

    def test_create(self):
        self.assertEqual(self.samples.severity, self.severity)
        self.assertEqual(self.samples.type, self.severity_type)
        self.assertEqual(self.samples.url, self.url)
        self.assertEqual(self.samples.extra, self.extra)
        self.assertEqual(self.samples.sid, self.sid)
        self.assertEqual(self.samples.dir, self.dir)


class SkipfishIssuesTest(TestCase):

    def setUp(self):
        self.pre_data = [{'severity': SkipfishRisk.NOTE, 'severity_type': 'test', 'directory': '', 'extra': '', 'sid': '', 'url': 'a'},
                    {'severity': SkipfishRisk.WARNING, 'severity_type': 'test', 'directory': '', 'extra': '', 'sid': '', 'url': 'b'},
                    {'severity': SkipfishRisk.LOW_RISK, 'severity_type': 'test2', 'directory': '', 'extra': '', 'sid': '', 'url': 'c'},
                    {'severity': SkipfishRisk.MEDIUM_RISK, 'severity_type': 'test2', 'directory': '', 'extra': '', 'sid': '', 'url': 'd'},]

        self.data = [SkipfishIssueSample(**pre) for pre in self.pre_data]
        self.issues = SkipfishIssues()

    def test_add(self):
        severity_type = 'Severity description'
        pre_data = {'severity': SkipfishRisk.NOTE, 'severity_type': severity_type, 'directory': '', 'extra': '', 'sid': '', 'url': ''}
        data = SkipfishIssueSample(**pre_data)
        self.issues.add(data)

        self.assertListEqual(self.issues._issues, [data])
        self.assertListEqual(self.issues._sorted_issues[SkipfishRisk.NOTE][severity_type], [data])

    def test_get_by_severity(self):
        for issue in self.data:
            self.issues.add(issue)

        self.assertListEqual(self.issues.get_by_severity(severity=SkipfishRisk.LOW_RISK), [self.data[2]])

    def test_str(self):
        for issue in self.data:
            self.issues.add(issue)

        result = str(self.issues)
        expected = '''{0}:
    {1}:
        {2}
{3}:
    {4}:
        {5}'''.format(SkipfishRisk.MEDIUM_RISK.description, self.pre_data[3]['severity_type'], self.pre_data[3]['url'],
                      SkipfishRisk.LOW_RISK.description, self.pre_data[2]['severity_type'], self.pre_data[2]['url'])

        self.assertEqual(result, expected)

    def test_bool(self):
        self.issues.add(self.data[0])
        self.assertFalse(False or self.issues)
        self.issues.add(self.data[1])
        self.assertFalse(False or self.issues)
        self.issues.add(self.data[2])
        self.assertTrue(False or self.issues)
        self.issues.add(self.data[3])
        self.assertTrue(False or self.issues)


class SkipfishRiskTesk(TestCase):
    def test_value_error(self):
        self.assertRaises(ValueError, SkipfishRisk.from_id, -1)