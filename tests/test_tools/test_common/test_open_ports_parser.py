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
<host endtime="1470387319"><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="800"><state state="closed" reason="syn-ack" reason_ttl="62"/></port></ports></host>
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

    BANNER_OUTPUT_XML = r'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.12 scan initiated Tue Aug 23 10:47:08 2016 as: nmap -n -&#45;privileged -oX - -T4 -p 0-1000 -sV 192.168.1.5 -->
<nmaprun scanner="nmap" args="nmap -n -&#45;privileged -oX - -T4 -p 0-1000 -sV 192.168.1.5" start="1471942028" startstr="Tue Aug 23 10:47:08 2016" version="7.12" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1001" services="0-1000"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1471942029" endtime="1471942067"><status state="up" reason="echo-reply" reason_ttl="62"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="closed" count="993">
<extrareasons reason="resets" count="993"/>
</extraports>
<port protocol="tcp" portid="993"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="imap" product="Dovecot imapd" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:dovecot:dovecot</cpe></service><script id="banner" output="test_banner"/></port>
</ports>
<times srtt="220492" rttvar="5732" to="243420"/>
</host>
<runstats><finished time="1471942067" timestr="Tue Aug 23 10:47:47 2016" elapsed="38.93" summary="Nmap done at Tue Aug 23 10:47:47 2016; 1 IP address (1 host up) scanned in 38.93 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
>>>>>>> Define ports/networks include/exclude values
</runstats>
</nmaprun>'''

    MASSCAN_OUTPUT = ET.fromstring(MASSSCAN_OUTPUT_XML)
    BANNER_OUTPUT = ET.fromstring(BANNER_OUTPUT_XML)
    NO_PORTS_ELEMENT = ET.fromstring(NO_PORTS_OUTPUT)

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

    def test_no_ports_scan(self):
        result = self.parser.parse(self.NO_PORTS_ELEMENT, self.node_by_ip)
        expected = []

        self.assertEqual(result, expected)

    def test_banner(self):
        result = self.parser.parse(self.BANNER_OUTPUT, self.node_by_ip)

        self.assertEqual(result[0].banner, 'test_banner')

