import ipaddress
import unittest
import xml.etree.ElementTree as ET

from structs import Node, TransportProtocol, Scan
from tools.common import OpenPortsParser


class OpenPortsParserTest(unittest.TestCase):
    NODE_IP = "127.0.0.1"
    NODE_NAME = "localhost"
    MASSSCAN_OUTPUT_XML = """<?xml version="1.0"?>
<!-- masscan v1.0 scan -->
<?xml-stylesheet href="" type="text/xsl"?>
<nmaprun scanner="masscan" start="1470387319" version="1.0-BETA"  xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" />
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="514"><state state="open" reason="syn-ack" reason_ttl="62"/></port></ports></host>
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="62"/></port></ports></host>
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="800"><state state="other" reason="syn-ack" reason_ttl="62"/></port></ports></host>
<runstats>
<finished time="1470387330" timestr="2016-08-05 10:55:30" elapsed="13" />
<hosts up="2" down="0" total="2" />
</runstats>
</nmaprun>
"""
    NO_PORTS_OUTPUT = """<?xml version="1.0"?>
<!-- masscan v1.0 scan -->
<?xml-stylesheet href="" type="text/xsl"?>
<nmaprun scanner="masscan" start="1470387319" version="1.0-BETA"  xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" />
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/></host>
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/></host>
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/></host>
<runstats>
<finished time="1470387330" timestr="2016-08-05 10:55:30" elapsed="13" />
<hosts up="2" down="0" total="2" />
</runstats>
</nmaprun>
    """
    MASSCAN_OUTPUT = ET.fromstring(MASSSCAN_OUTPUT_XML)
    NO_PORTS_ELEMENT = ET.fromstring(NO_PORTS_OUTPUT)

    def setUp(self):
        self.parser = OpenPortsParser()
        self.node = Node(ip=ipaddress.ip_address(self.NODE_IP), node_id=None)
        self.node.name = self.NODE_NAME
        self.node.scan = Scan()
        self.node_by_ip = {self.node.ip: self.node}

    def test_parse_masscan(self):
        ports = self.parser.parse(self.MASSCAN_OUTPUT, self.node_by_ip)

        self.assertEqual(len(ports), 2)

        self.assertEqual(ports[0].number, 514)
        self.assertEqual(ports[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(ports[0].node, self.node)

        self.assertEqual(ports[1].number, 80)
        self.assertEqual(ports[1].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(ports[1].node, self.node)

    def test_no_ports_scan(self):
        result = self.parser.parse(self.NO_PORTS_ELEMENT, self.node_by_ip)
        expected = []

        self.assertEqual(result, expected)
