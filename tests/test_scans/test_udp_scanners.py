from unittest import TestCase
from unittest.mock import MagicMock, patch, call

from scans.udp_scanner import UDPScanner


class UDPScannerTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.task = UDPScanner(aucote=self.aucote, scan_only=False)

    @patch('scans.udp_scanner.PortsScan')
    def test_scanners(self, scan):
        result = self.task.scanners
        expected = {
            self.task.IPV4: [scan.return_value],
            self.task.IPV6: [scan.return_value],
        }

        self.assertEqual(result, expected)
        scan.assert_has_calls((call(ipv6=False, tcp=False, udp=True), call(ipv6=True, tcp=False, udp=True)))
