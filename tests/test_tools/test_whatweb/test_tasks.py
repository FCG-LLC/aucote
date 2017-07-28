import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan
from tools.whatweb.base import WhatWebBase
from tools.whatweb.tasks import WhatWebTask


class WhatWebTaskTest(TestCase):
    def setUp(self):
        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        self.port = Port(node=self.node, number=19, transport_protocol=TransportProtocol.UDP)
        self.port.protocol = 'http'
        self.aucote = MagicMock()
        self.exploit = Exploit(app='whatweb', name='whatweb', exploit_id=1)
        self.scan = Scan()
        self.task = WhatWebTask(port=self.port, aucote=self.aucote, exploits=[self.exploit], scan=self.scan)

    def test_init(self):
        self.assertIsInstance(self.task.command, WhatWebBase)

    def test_prepare_args(self):
        result = self.task.prepare_args()
        expected = 'http://127.0.0.1:19',
        self.assertEqual(result, expected)
