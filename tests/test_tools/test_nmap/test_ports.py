import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock
from xml.etree import ElementTree

from structs import Node
from tools.nmap.ports import PortsScan


class PortScanTest(TestCase):

    OUTPUT = r'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.12 scan initiated Tue Aug 23 10:47:08 2016 as: nmap -n -&#45;privileged -oX - -T4 -p 0-1000 -sV 192.168.1.5 -->
<nmaprun scanner="nmap" args="nmap -n -&#45;privileged -oX - -T4 -p 0-1000 -sV 192.168.1.5" start="1471942028" startstr="Tue Aug 23 10:47:08 2016" version="7.12" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1001" services="0-1000"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1471942029" endtime="1471942067"><status state="up" reason="echo-reply" reason_ttl="62"/>
<address addr="192.168.1.5" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="closed" count="993">
<extrareasons reason="resets" count="993"/>
</extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="ssh" product="OpenSSH" version="5.3p1 Debian 3ubuntu7" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:5.3p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="25"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="smtp" product="Postfix smtpd" hostname=" mail.respecs.org" method="probed" conf="10"><cpe>cpe:/a:postfix:postfix</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="http" product="Apache httpd" version="2.2.14" extrainfo="(Ubuntu)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.2.14</cpe></service></port>
<port protocol="tcp" portid="110"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="pop3" product="Dovecot pop3d" method="probed" conf="10"><cpe>cpe:/a:dovecot:dovecot</cpe></service></port>
<port protocol="tcp" portid="143"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="imap" product="Dovecot imapd" method="probed" conf="10"><cpe>cpe:/a:dovecot:dovecot</cpe></service></port>
<port protocol="tcp" portid="587"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="smtp" product="Postfix smtpd" hostname=" mail.respecs.org" method="probed" conf="10"><cpe>cpe:/a:postfix:postfix</cpe></service></port>
<port protocol="tcp" portid="993"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="imap" product="Dovecot imapd" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:dovecot:dovecot</cpe></service><script id="banner" output="* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID &#xa;ENABLE AUTH=PLAIN AUTH=LOGIN] Dovecot ready."/></port>
<port protocol="tcp" portid="995"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="pop3" product="Dovecot pop3d" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:dovecot:dovecot</cpe></service></port>
<port protocol="tcp" portid="112"><state state="other" reason="syn-ack" reason_ttl="62"/><service name="pop3" product="Dovecot pop3d" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:dovecot:dovecot</cpe></service></port>
</ports>
<times srtt="220492" rttvar="5732" to="243420"/>
</host>
<runstats><finished time="1471942067" timestr="Tue Aug 23 10:47:47 2016" elapsed="38.93" summary="Nmap done at Tue Aug 23 10:47:47 2016; 1 IP address (1 host up) scanned in 38.93 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

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

    def setUp(self):
        self.executor = MagicMock()
        self.kudu_queue = MagicMock()
        self.scanner = PortsScan(executor=self.executor)
        node = Node(ip = ipaddress.ip_address('192.168.1.5'), node_id=None)
        self.nodes = [node]

    def test_scan_ports(self):
        self.scanner.call = MagicMock(return_value = ElementTree.fromstring(self.OUTPUT))

        result = self.scanner.scan_ports(nodes=self.nodes)
        self.assertEqual(len(result), 8)
        self.scanner.call.assert_called_once_with(['-n', '--privileged', '-oX', '-', '-T4', '-p', '0-65535', '-sV', '--script', 'banner', '192.168.1.5'])

    def test_scan_custom_ports(self):
        self.scanner.call = MagicMock(return_value = ElementTree.fromstring(self.OUTPUT))

        result = self.scanner.scan_ports(nodes=self.nodes, ports=[80, 43])
        self.assertEqual(len(result), 8)
        self.scanner.call.assert_called_once_with(['-n', '--privileged', '-oX', '-', '-T4', '-p', '80,43', '-sV', '--script', 'banner', '192.168.1.5'])

    def test_no_ports(self):
        self.scanner.call = MagicMock(return_value = ElementTree.fromstring(self.NO_PORTS_OUTPUT))
        result = self.scanner.scan_ports(nodes=self.nodes, ports=[80, 43])
        expected = []

        self.assertEqual(result, expected)
