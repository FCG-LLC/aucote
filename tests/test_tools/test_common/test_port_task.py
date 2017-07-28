from unittest import TestCase
from unittest.mock import MagicMock, patch, call

from fixtures.exploits import Exploit
from structs import Port, Scan, Node, Vulnerability, VulnerabilityChange
from tools.common.port_task import PortTask


class PortTaskTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.port = Port(node=MagicMock(), transport_protocol=None, number=MagicMock())
        self.exploit = MagicMock()
        self.scan = Scan()
        self.task = PortTask(aucote=self.aucote, port=self.port, exploits=[self.exploit], scan=self.scan)

    def test_init(self):
        self.assertEqual(self.task._port, self.port)
        self.assertEqual(self.task.aucote, self.aucote)
        self.assertEqual(self.task.exploit, self.exploit)

    def test_exploit_one(self):
        self.assertEqual(self.task.exploit, self.exploit)

    def test_exploit_multiple(self):
        self.task.current_exploits = [MagicMock(), MagicMock()]
        self.assertEqual(self.task.exploit, None)

    def test_get_vulnerabilities(self):
        self.assertRaises(NotImplementedError, self.task.get_vulnerabilities, [])

    def test_port(self):
        self.assertEqual(self.task.port, self.port)

    @patch('tools.common.port_task.Serializer.serialize_vulnerability_change')
    @patch('tools.common.port_task.time.time', MagicMock(return_value=12))
    def test_diff_two_last_scans(self, serializer):
        exploit = Exploit(exploit_id=1)
        self.task._current_exploits = [self.exploit]
        scan_2 = Scan()
        scans = [self.scan, scan_2]
        self.task.storage.get_scans_by_security_scan.return_value = scans
        vuln_added = Vulnerability(port=self.port, exploit=exploit, subid=3, output='a')
        vuln_removed = Vulnerability(port=self.port, exploit=exploit, subid=1, output='b')
        vuln_changed_1 = Vulnerability(port=self.port, exploit=exploit, subid=2, output='c')
        vuln_changed_2 = Vulnerability(port=self.port, exploit=exploit, subid=2, output='d')
        vuln_common = Vulnerability(port=self.port, exploit=exploit, subid=5, output='e')
        self.task.storage.get_vulnerabilities.side_effect = ([vuln_added, vuln_changed_1, vuln_common],
                                                             [vuln_removed, vuln_changed_2, vuln_common])

        expected = [
            VulnerabilityChange(change_time=12, previous_finding=None, current_finding=vuln_added),
            VulnerabilityChange(change_time=12, previous_finding=vuln_removed, current_finding=None),
            VulnerabilityChange(change_time=12, previous_finding=vuln_changed_2, current_finding=vuln_changed_1),
        ]

        self.task.diff_with_last_scan()

        self.task.storage.get_vulnerabilities.assert_has_calls((
            call(port=self.port, exploit=self.exploit, scan=self.scan),
            call(port=self.port, exploit=self.exploit, scan=scan_2)
        ), any_order=True)

        self.task.storage.save_changes.assert_called_once_with(expected)
        serializer.assert_has_calls((call(vuln) for vuln in expected))

    @patch('tools.common.port_task.Serializer.serialize_vulnerability_change')
    @patch('tools.common.port_task.time.time', MagicMock(return_value=12))
    def test_diff_two_last_scans_first_scan(self, serializer):
        exploit = Exploit(exploit_id=1)
        self.task._current_exploits = [self.exploit]
        scans = [self.scan]
        self.task.storage.get_scans_by_security_scan.return_value = scans
        vuln_added = Vulnerability(port=self.port, exploit=exploit, subid=3, output='a')
        vuln_changed_1 = Vulnerability(port=self.port, exploit=exploit, subid=2, output='c')
        self.task.storage.get_vulnerabilities.return_value = [vuln_added, vuln_changed_1]

        expected = [
            VulnerabilityChange(change_time=12, previous_finding=None, current_finding=vuln_added),
            VulnerabilityChange(change_time=12, previous_finding=None, current_finding=vuln_changed_1)
        ]

        self.task.diff_with_last_scan()

        self.task.storage.get_vulnerabilities.assert_has_calls((
            call(port=self.port, exploit=self.exploit, scan=self.scan),
        ))

        self.task.storage.save_changes.assert_called_once_with(expected)
        serializer.assert_has_calls((call(vuln) for vuln in expected), any_order=True)
