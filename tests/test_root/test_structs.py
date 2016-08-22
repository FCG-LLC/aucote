from unittest import TestCase

from structs import RiskLevel
from structs import TransportProtocol


class StructsTest(TestCase):

    def test_transport_protocol_exception(self):
        self.assertRaises(ValueError, TransportProtocol.from_nmap_name, '')

    def test_risk_level_exception(self):
        self.assertRaises(ValueError, RiskLevel.from_name, '')