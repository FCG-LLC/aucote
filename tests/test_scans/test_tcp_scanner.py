from unittest import TestCase
from unittest.mock import MagicMock, patch

from scans.tcp_scanner import TCPScanner


class TCPScannerTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.scanner = TCPScanner(aucote=self.aucote, as_service=False, host='localhost', port=1339)

    def test_scanners(self):
        result = self.scanner.scanners
        expected = {
            self.scanner.IPV4: [self.scanner._tcp_scanner],
            self.scanner.IPV6: [self.scanner._tcp_scanner]
        }

        self.assertEqual(result, expected)
