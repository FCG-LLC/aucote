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

    BANNER_XML = r'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.40 scan initiated Wed Feb 15 15:54:54 2017 as: nmap -oX - -p 22 -&#45;script banner localhost -->
<nmaprun scanner="nmap" args="nmap -oX - -p 22 -&#45;script banner localhost" start="1487170494" startstr="Wed Feb 15 15:54:54 2017" version="7.40" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1487170494" endtime="1487170494"><status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="user"/>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" method="table" conf="3"/><script id="banner" output="SSH-2.0-OpenSSH_7.4p1 Debian-6"/></port>
</ports>
<times srtt="149" rttvar="5000" to="100000"/>
</host>
<runstats><finished time="1487170494" timestr="Wed Feb 15 15:54:54 2017" elapsed="0.80" summary="Nmap done at Wed Feb 15 15:54:54 2017; 1 IP address (1 host up) scanned in 0.80 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    MASSCAN_OUTPUT = ET.fromstring(MASSSCAN_OUTPUT_XML)
    NO_PORTS_ELEMENT = ET.fromstring(NO_PORTS_OUTPUT)
    BANNER_OUTPUT = ET.fromstring(BANNER_XML)

    def setUp(self):
        self.parser = OpenPortsParser()
        self.node = Node(ip=ipaddress.ip_address(self.NODE_IP), node_id=None)
        self.node.name = self.NODE_NAME
        self.node.scan = Scan(start=1234)
        self.node_by_ip = {self.node.ip: self.node}

    def test_parse_masscan(self):
        ports = self.parser.parse(self.MASSCAN_OUTPUT, self.node_by_ip)

        self.assertEqual(len(ports), 2)

        self.assertEqual(ports[0].number, 514)
        self.assertEqual(ports[0].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(ports[0].node, self.node)
        self.assertEqual(ports[0].scan.start, 1234)

        self.assertEqual(ports[1].number, 80)
        self.assertEqual(ports[1].transport_protocol, TransportProtocol.TCP)
        self.assertEqual(ports[1].node, self.node)
        self.assertEqual(ports[1].scan.start, 1234)

    def test_parse_with_banner(self):
        self.node_by_ip = {self.node.ip: self.node}
        ports = self.parser.parse(self.BANNER_OUTPUT, self.node_by_ip)
        self.assertEqual(ports[0].banner, 'SSH-2.0-OpenSSH_7.4p1 Debian-6')

    def test_no_ports_scan(self):
        result = self.parser.parse(self.NO_PORTS_ELEMENT, self.node_by_ip)
        expected = []

        self.assertEqual(result, expected)
