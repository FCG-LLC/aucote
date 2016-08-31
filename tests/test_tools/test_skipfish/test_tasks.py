import ipaddress
import subprocess
from unittest import TestCase
from unittest.mock import MagicMock

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
        self.port = Port()
        self.port.transport_protocol = TransportProtocol.TCP
        self.port.node = Node()
        self.port.node.id = 1
        self.port.node.ip = ipaddress.ip_address('127.0.0.1')
        self.port.number = 80
        self.port.scan = Scan()

        self.task = SkipfishScanTask(executor=self.executor, port=self.port)
        self.task.executor.exploits.find.return_value = Exploit(id=1)

    def test_call(self):
        expected = MagicMock()
        self.task.call = MagicMock(return_value=expected)
        result = self.task()

        self.assertEqual(result, expected)

    def test_call_exception(self):
        self.task.call = MagicMock(side_effect=subprocess.CalledProcessError(MagicMock(), MagicMock()))
        result = self.task()

        self.assertEqual(result, None)
