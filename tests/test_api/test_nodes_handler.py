import json
from tests.test_api.test_api import APITest


class NodesHandlerTest(APITest):
    def setUp(self):
        super(NodesHandlerTest, self).setUp()

    def test_nodes_scans(self):
        self.maxDiff = None
        expected = {
            'nodes':
                [
                    {
                        'id': 2,
                        'ip': '10.156.67.34',
                        'node_id': 75,
                        'scan': 2,
                        'scan_url': self.get_url('/api/v1/scan/2'),
                        'url': self.get_url('/api/v1/node/2')
                    },
                    {
                        'id': 3,
                        'ip': '10.156.67.18',
                        'node_id': 13,
                        'scan': 2,
                        'scan_url': self.get_url('/api/v1/scan/2'),
                        'url': self.get_url('/api/v1/node/3')
                    },
                    {
                        'id': 1,
                        'ip': '10.156.67.18',
                        'node_id': 13,
                        'scan': 1,
                        'scan_url': self.get_url('/api/v1/scan/1'),
                        'url': self.get_url('/api/v1/node/1')
                    }
                ]
        }

        response = self.fetch('/api/v1/nodes', method='GET')
        
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['navigation']
        del result['meta']
        self.assertEqual(result, expected)

    def test_node_details(self):
        expected = {
            'id': 1,
            'ip': '10.156.67.18',
            'node_id': 13,
            'scan': 1,
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
            'url': self.get_url('/api/v1/node/1')
        }

        response = self.fetch('/api/v1/node/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['meta']
        self.assertEqual(result, expected)
