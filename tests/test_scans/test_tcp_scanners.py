from unittest import TestCase
from unittest.mock import MagicMock, patch

from scans.tcp_scanner import TCPScanner


class TCPScannerTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.task = TCPScanner(aucote=self.aucote, scan_only=False)

    @patch('scans.tcp_scanner.MasscanPorts')
    @patch('scans.tcp_scanner.PortsScan')
    def test_scanners(self, scan, masscan):
        result = self.task.scanners
        expected = {
            self.task.IPV4: [masscan.return_value],
            self.task.IPV6: [scan.return_value],
        }

        self.assertEqual(result, expected)
        scan.assert_called_once_with(ipv6=True, tcp=True, udp=False)
        masscan.assert_called_once_with(udp=False)
