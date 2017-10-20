import json
from tests.test_api.test_api import APITest


class VulnerabilitiesHandlerTest(APITest):
    def setUp(self):
        super(VulnerabilitiesHandlerTest, self).setUp()

    def test_vulnerabilities(self):
        expected = {
            'vulnerabilitites':
                [
                    {'cvss': 6.8,
                     'exploit': 14,
                     'id': 2,
                     'output': 'Vulnerable stuff',
                     'port': '10.156.67.18:34',
                     'scan': {
                         'end': 447,
                         'end_human': '1970-01-01T00:07:27+00:00',
                         'id': 2,
                         'protocol': 'UDP',
                         'scanner': 'udp',
                         'scanner_url': self.get_url('/api/v1/scanner/udp'),
                         'start': 230,
                         'start_human': '1970-01-01T00:03:50+00:00',
                         'url': self.get_url('/api/v1/scan/2')
                     },
                     'time': 718,
                     'time_human': '1970-01-01T00:11:58+00:00',
                     'url': self.get_url('/api/v1/vulnerability/2'),
                     'vuln_subid': 34},
                    {'cvss': 6.8,
                     'exploit': 14,
                     'id': 1,
                     'output': 'Vulnerable stuff',
                     'port': '10.156.67.18:34',
                     'scan': {
                         'end': 446,
                         'end_human': '1970-01-01T00:07:26+00:00',
                         'id': 1,
                         'protocol': 'TCP',
                         'scanner': 'tcp',
                         'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                         'start': 123,
                         'start_human': '1970-01-01T00:02:03+00:00',
                         'url': self.get_url('/api/v1/scan/1')
                     },
                     'time': 134,
                     'time_human': '1970-01-01T00:02:14+00:00',
                     'url': self.get_url('/api/v1/vulnerability/1'),
                     'vuln_subid': 34
                     }
                ]
        }

        response = self.fetch('/api/v1/vulnerabilities', method='GET')

        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['navigation']
        del result['meta']
        self.assertEqual(result, expected)

    def test_vulnerability(self):
        expected = {
            'exploit': 14,
            'id': 1,
            'output': 'Vulnerable stuff',
            'port': {'node_id': 13,
                     'node_ip': '10.156.67.18',
                     'port_number': 34,
                     'protocol': 'UDP'},
            'scan': {'end': 446,
                     'end_human': '1970-01-01T00:07:26+00:00',
                     'id': 1,
                     'protocol': 'TCP',
                     'scanner': 'tcp',
                     'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                     'start': 123,
                     'start_human': '1970-01-01T00:02:03+00:00',
                     'url': self.get_url('/api/v1/scan/1')},
            'scans': [{'end': 447,
                       'end_human': '1970-01-01T00:07:27+00:00',
                       'id': 2,
                       'protocol': 'UDP',
                       'scanner': 'udp',
                       'scanner_url': self.get_url('/api/v1/scanner/udp'),
                       'start': 230,
                       'start_human': '1970-01-01T00:03:50+00:00',
                       'url': self.get_url('/api/v1/scan/2')},
                      {'end': 446,
                       'end_human': '1970-01-01T00:07:26+00:00',
                       'id': 1,
                       'protocol': 'TCP',
                       'scanner': 'tcp',
                       'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                       'start': 123,
                       'start_human': '1970-01-01T00:02:03+00:00',
                       'url': self.get_url('/api/v1/scan/1')}],
            'time': 134,
            'time_human': '1970-01-01T00:02:14+00:00',
            'url': self.get_url('/api/v1/sec_scan/1')}

        response = self.fetch('/api/v1/vulnerability/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['meta']
        self.assertEqual(result, expected)
