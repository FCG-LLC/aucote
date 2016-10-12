import ipaddress
import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from fixtures.exploits import Exploit
from structs import Port, TransportProtocol, Node, Scan
from tools.skipfish.tasks import SkipfishScanTask


class SkipfishScanTaskTest(TestCase):
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
        self.executor = MagicMock()

        self.node = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))
        self.port = Port(transport_protocol=TransportProtocol.TCP, number = 80, node=self.node)
        self.port.scan = Scan()
        self.exploit = Exploit(exploit_id=1)

        self.task = SkipfishScanTask(executor=self.executor, port=self.port, exploit=self.exploit)
        self.task.executor.exploits.find.return_value = self.exploit
        self.task.store_scan_end = MagicMock()

    @patch('time.time', MagicMock(return_value=27.0))
    def test_storage(self):
        self.task.command.call = MagicMock(return_value=MagicMock())
        self.task()

        result = self.task.store_scan_end.call_args[1]
        expected = {
            'exploits': [self.exploit],
            'port': self.port,
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(self.port.scan.end, 27)
