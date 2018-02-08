import ipaddress
import tempfile
from unittest.mock import MagicMock

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan
from tools.aucote_scripts.tasks.siet import SietTask


class SietTaskTest(AsyncTestCase):
    def setUp(self):
        super(SietTaskTest, self).setUp()
        self.context = MagicMock()
        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=14)
        self.scan = Scan()
        self.port = Port(node=self.node, number=46, transport_protocol=TransportProtocol.TCP, scan=self.scan)
        self.exploit = Exploit(exploit_id=15, app='aucote-scripts', name='siet')
        self.task = SietTask(context=self.context, port=self.port, scan=self.scan, exploits=[self.exploit])

    @gen_test
    async def test_call(self):
        test_file = tempfile.NamedTemporaryFile()

        test_file.write(b"""line 1
line 2
line 3
line 4
line 5
line 6
line 7
line 8
line 9
line 10
line 11
line 12
hostname asd
line 13
line 14
line 15""")

        test_file.seek(0)
        self.context.aucote.tftp_server.async_get_file = MagicMock(return_value=Future())
        self.context.aucote.tftp_server.async_get_file.return_value.set_result(test_file.name)

        await self.task()
