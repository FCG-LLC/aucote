import json
from tests.test_api.test_api import APITest


class PortsHandlerTest(APITest):
    def setUp(self):
        super(PortsHandlerTest, self).setUp()

    def test_ports_scans(self):
        self.maxDiff = None
        expected = {
            'ports':
                [
                    {
                        'id': 2,
                        'port': {
                            'node': {
                                'id': 75,
                                'ip': '10.156.67.34'
                            },
                            'port_number': 78,
                            'protocol': 'TCP'
                        },
                        'scan': 1,
                        'timestamp': 2345,
                        'timestamp_human': '1970-01-01T00:39:05+00:00',
                        'url': self.get_url('/api/v1/ports/2')
                    },
                    {
                        'id': 1,
                        'port': {
                            'node': {
                                'id': 13,
                                'ip': '10.156.67.18'
                            },
                            'port_number': 34,
                            'protocol': 'UDP'
                        },
                        'scan': 1,
                        'timestamp': 1234,
                        'timestamp_human': '1970-01-01T00:20:34+00:00',
                        'url': self.get_url('/api/v1/ports/1')
                    }
                ]
        }

        response = self.fetch('/api/v1/ports', method='GET')

        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['navigation']
        del result['meta']
        self.assertEqual(result, expected)

    def test_port_details(self):
        expected = {
            'id': 1,
            'node': {
                'id': 13,
                'ip': '10.156.67.18'
            },
            'port_number': 34,
            'protocol': 'UDP',
            'scan': 1,
            'scan_url': self.get_url('/api/v1/scans/1'),
            'scans':
                [
                    {
                        'end_human': '1970-01-01T00:07:26+00:00',
                        'start_human': '1970-01-01T00:02:03+00:00',
                        'end': 446,
                        'id': 1,
                        'protocol': 'TCP',
                        'scanner': 'tcp',
                        'scanner_url': self.get_url('/api/v1/scanners/tcp'),
                        'start': 123,
                        'url': self.get_url('/api/v1/scans/1')
                    }
                ],
            'timestamp': 1234,
            'human_timestamp': '1970-01-01T00:20:34+00:00',
            'url': self.get_url('/api/v1/ports/1')
        }

        response = self.fetch('/api/v1/ports/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['meta']
        self.assertEqual(result, expected)
