import json
from tests.test_api.test_api import APITest


class NodesHandlerTest(APITest):
    def setUp(self):
        super(NodesHandlerTest, self).setUp()

    def test_nodes_scans(self):
        self.maxDiff = None
        expected = {
            'navigation': {
                'limit': 10,
                'next_page': self.get_url('/api/v1/nodes?limit=10&page=1'),
                'page': 0,
                'previous_page': self.get_url('/api/v1/nodes?limit=10&page=0')
            },
            'nodes':
                [
                    {
                        'id': 2,
                        'ip': '10.156.67.34',
                        'node_id': 75,
                        'scan': 'udp',
                        'url': self.get_url('/api/v1/nodes/2')
                    },
                    {
                        'id': 3,
                        'ip': '10.156.67.18',
                        'node_id': 13,
                        'scan': 'udp',
                        'url': self.get_url('/api/v1/nodes/3')
                    },
                    {
                        'id': 1,
                        'ip': '10.156.67.18',
                        'node_id': 13,
                        'scan': 'tcp',
                        'url': self.get_url('/api/v1/nodes/1')
                    }
                ]
        }

        response = self.fetch('/api/v1/nodes', method='GET')
        
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['meta']
        self.assertEqual(result, expected)

    def test_node_details(self):
        expected = {
            'id': 1,
            'ip': '10.156.67.18',
            'node_id': 13,
            'scan':
                {
                    'end': 446,
                    'end_human': '1970-01-01T00:07:26+00:00',
                    'id': 1,
                    'protocol': 'TCP',
                    'scanner': 'tcp',
                    'start': 123,
                    'start_human': '1970-01-01T00:02:03+00:00',
                    'url': self.get_url('/api/v1/scans/1')
                },
            'scans': [
                {
                    'end': 447,
                    'end_human': '1970-01-01T00:07:27+00:00',
                    'start_human': '1970-01-01T00:03:50+00:00',
                    'id': 2,
                    'protocol': 'UDP',
                    'scanner': 'udp',
                    'start': 230,
                    'url': self.get_url('/api/v1/scans/2')
                },
                {
                    'end_human': '1970-01-01T00:07:26+00:00',
                    'start_human': '1970-01-01T00:02:03+00:00',
                    'end': 446,
                    'id': 1,
                    'protocol': 'TCP',
                    'scanner': 'tcp',
                    'start': 123,
                    'url': self.get_url('/api/v1/scans/1')
                }
            ],
            'url': self.get_url('/api/v1/nodes/1')
        }

        response = self.fetch('/api/v1/nodes/1', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        result = json.loads(response.body.decode())
        del result['meta']
        self.assertEqual(result, expected)
