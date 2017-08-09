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
