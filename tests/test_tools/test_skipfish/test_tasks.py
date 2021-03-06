import ipaddress
from unittest.mock import MagicMock, patch

from tornado.concurrent import Future
from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from scans.tcp_scanner import TCPScanner
from structs import Port, TransportProtocol, Node, Scan, ScanContext
from tools.skipfish.tasks import SkipfishScanTask
from utils import Config


class SkipfishScanTaskTest(AsyncTestCase):
    OUTPUT = '''[*] Scan in progress, please stay tuned...

[!] Scan aborted by user, bailing out!
[+] Copying static resources...
[+] Sorting and annotating crawl nodes: 16
[+] Looking for duplicate entries: 16
[+] Counting unique nodes: 15
[+] Saving pivot data for third-party tools...
[+] Writing scan description...
[+] Writing crawl tree: 16
[+] Generating summary views...
[+] Report saved to '/tmp/skipfish_Tue Aug 30 14:17:33 CEST 2016/index.html' [0x7951b064].
[+] This was a great day for science!'''

    def setUp(self):
        super(SkipfishScanTaskTest, self).setUp()
        self.aucote = MagicMock()

        self.node = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        self.port = Port(transport_protocol=TransportProtocol.TCP, number=80, node=self.node)
        self.port.scan = Scan()
        self.exploit = Exploit(exploit_id=1)
        self.scan = Scan()
        self.context = ScanContext(aucote=self.aucote,
                                   scanner=TCPScanner(MagicMock(), MagicMock(), MagicMock(), MagicMock()))

        self.task = SkipfishScanTask(context=self.context, port=self.port, exploits=[self.exploit])
        self.task.aucote.exploits.find.return_value = self.exploit
        self.task.store_scan_end = MagicMock()

    @patch('time.time', MagicMock(return_value=27.0))
    @patch('tools.common.command_task.cfg', new_callable=Config)
    @patch('scans.scan_async_task.cfg', new_callable=Config)
    @patch('tools.skipfish.tasks.cfg', new_callable=Config)
    @gen_test
    async def test_storage(self, cfg, cfg_scan, cfg_comm_task):
        cfg_comm_task._cfg = cfg_scan._cfg = cfg._cfg = {
            'tools': {
                'skipfish': {
                    'threads': 30,
                    'limit': 0,
                    'tmp_directory': '/tmp',
                    'timeout': 0
                }
            },
            'portdetection': {
                'expiration_period': '7d'
            }
        }
        future = Future()
        future.set_result(MagicMock())
        self.task.command.async_call = MagicMock(return_value=future)
        await self.task()

        result = self.task.store_scan_end.call_args[1]
        expected = {
            'exploits': [self.exploit],
            'port': self.port,
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(self.port.scan.end, 27)
