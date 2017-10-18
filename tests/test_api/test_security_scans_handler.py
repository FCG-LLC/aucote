import json
from tests.test_api.test_api import APITest


class SecurityScansHandlerTest(APITest):
    def setUp(self):
        super(SecurityScansHandlerTest, self).setUp()

    def test_security_scans(self):
        self.maxDiff = None
        expected = {
            'security_scans':
                [
                    {
                        'exploit':
                            {
                                'app': 'test_app',
                                'id': 14,
                                'name': 'test_name'
                            },
                        'id': 3,
                        'port':
                            {
                                'node_id': 13,
                                'node_ip': '10.156.67.18',
                                'port_number': 34,
                                'protocol': 'UDP'
                            },
                        'scan_start': 114.0,
                        'scan':
                            {
                                'end': 447,
                                'id': 2,
                                'protocol': 'UDP',
                                'scanner': 'udp',
                                'scanner_url': self.get_url('/api/v1/scanner/udp'),
                                'start': 230,
                                'url': self.get_url('/api/v1/scan/2')
                            },
                        'scan_end': 981.0,
                        'url': self.get_url('/api/v1/sec_scan/3')
                    },
                    {
                        'exploit':
                         {
                             'app': 'test_app',
                             'id': 14,
                             'name': 'test_name'
                         },
                        'id': 1,
                        'port':
                            {
                                'node_id': 13,
                                'node_ip': '10.156.67.18',
                                'port_number': 34,
                                'protocol': 'UDP'
                            },
                        'scan_start': 178.0,
                        'scan':
                            {
                                'end': 446,
                                'id': 1,
                                'protocol': 'TCP',
                                'scanner': 'tcp',
                                'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                                'start': 123,
                                'url': self.get_url('/api/v1/scan/1')
                            },
                        'scan_end': 851.0,
                        'url': self.get_url('/api/v1/sec_scan/1')
                    },
                    {
                        'exploit':
                            {
                                'app': 'test_app_2',
                                'id': 2,
                                'name': 'test_name_2'
                            },
                        'id': 2,
                        'port':
                            {
                                'node_id': 13,
                                'node_ip': '10.156.67.18',
                                'port_number': 34,
                                'protocol': 'UDP'
                            },
                        'scan_start': 109.0,
                        'scan':
                            {
                                'end': 446,
                                'id': 1,
                                'protocol': 'TCP',
                                'scanner': 'tcp',
                                'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                                'start': 123,
                                'url': self.get_url('/api/v1/scan/1')
                            },
                        'scan_end': 775.0,
                        'url': self.get_url('/api/v1/sec_scan/2')
                    }
                ]
        }

        response = self.fetch('/api/v1/sec_scans', method='GET')
        
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    def test_node_details(self):
        expected = {
            'exploit': {
                'app': 'test_app', 'id': 14, 'name': 'test_name'
            },
            'id': 1,
            'port': {
                'node_id': 13,
                'node_ip': '10.156.67.18',
                'port_number': 34,
                'protocol': 'UDP'
            },
            'scan_start': 178.0,
            'scan': {
                'end': 446,
                'id': 1,
                'protocol': 'TCP',
                'scanner': 'tcp',
                'scanner_url':self.get_url('/api/v1/scanner/tcp'),
                'start': 123,
                'url': self.get_url('/api/v1/scan/1')
            },
            'scan_end': 851.0,
            'scan_url': self.get_url('/api/v1/scan/1'),
            'scans': [
                {
                    'end': 447,
                    'id': 2,
                    'protocol': 'UDP',
                    'scanner': 'udp',
                    'scanner_url': self.get_url('/api/v1/scanner/udp'),
                    'start': 230,
                    'url': self.get_url('/api/v1/scan/2')
                },
                {
                    'end': 446,
                    'id': 1,
                    'protocol': 'TCP',
                    'scanner': 'tcp',
                    'scanner_url': self.get_url('/api/v1/scanner/tcp'),
                    'start': 123,
                    'url': self.get_url('/api/v1/scan/1')
                }
            ],
            'url': self.get_url('/api/v1/sec_scan/1')
        }

        response = self.fetch('/api/v1/sec_scan/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)
