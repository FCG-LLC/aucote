import ipaddress
import unittest
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from structs import Port, TransportProtocol, Node

from tools.nmap.tasks.port_info import NmapPortInfoTask


@patch('scans.task_mapper.TaskMapper', MagicMock)
class NmapPortInfoTaskTest(unittest.TestCase):
    XML = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.12 scan initiated Tue Aug  9 11:04:25 2016 as: nmap -oX - -sU -p 123 -&#45;script banner 192.168.2.1 -->
<nmaprun scanner="nmap" args="nmap -oX - -sU -p 123 -&#45;script banner 192.168.2.1" start="1470733465" startstr="Tue Aug  9 11:04:25 2016" version="7.12" xmloutputversion="1.04">
<scaninfo type="udp" protocol="udp" numservices="1" services="123"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1470733466" endtime="1470733467"><status state="up" reason="echo-reply" reason_ttl="253"/>
<address addr="192.168.2.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="253"/><service version="1.2.3" name="ntp" method="table" conf="3"/></port>
</ports>
<times srtt="255573" rttvar="196403" to="1041185"/>
</host>
<runstats><finished time="1470733467" timestr="Tue Aug  9 11:04:27 2016" elapsed="1.63" summary="Nmap done at Tue Aug  9 11:04:27 2016; 1 IP address (1 host up) scanned in 1.63 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    XML_BANNER = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.12 scan initiated Tue Aug  9 11:04:25 2016 as: nmap -oX - -sU -p 123 -&#45;script banner 192.168.2.1 -->
<nmaprun scanner="nmap" args="nmap -oX - -sU -p 123 -&#45;script banner 192.168.2.1" start="1470733465" startstr="Tue Aug  9 11:04:25 2016" version="7.12" xmloutputversion="1.04">
<scaninfo type="udp" protocol="udp" numservices="1" services="123"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1470733466" endtime="1470733467"><status state="up" reason="echo-reply" reason_ttl="253"/>
<address addr="192.168.2.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="253"/><script id="banner" output="SSH-1.99-Cisco-1.25"/></port>
</ports>
<times srtt="255573" rttvar="196403" to="1041185"/>
</host>
<runstats><finished time="1470733467" timestr="Tue Aug  9 11:04:27 2016" elapsed="1.63" summary="Nmap done at Tue Aug  9 11:04:27 2016; 1 IP address (1 host up) scanned in 1.63 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    def setUp(self):
        self.executor = MagicMock()

        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)

        self.port = Port(number=22, transport_protocol=TransportProtocol.TCP, node=self.node)

        self.port_info = NmapPortInfoTask(executor=self.executor, port=self.port)
        self.port_info.call = MagicMock(return_value=ElementTree.fromstring(self.XML))

    def test_tcp_scan(self):
        self.port_info()

        result = self.port_info.call.call_args[1].get('args', [])

        self.assertIn('-p', result)
        self.assertIn('22', result)
        self.assertIn('-sV', result)
        self.assertIn('--script', result)
        self.assertIn('banner', result)
        self.assertIn(str(self.port.node.ip), result)

    def test_init(self):
        self.assertEqual(self.port_info.executor, self.executor)

    def test_udp_scan(self):
        self.port_info._port.transport_protocol = TransportProtocol.UDP
        self.port_info()

        result = self.port_info.call.call_args[1].get('args', [])

        self.assertIn('-p', result)
        self.assertIn('22', result)
        self.assertIn('-sV', result)
        self.assertIn('--script', result)
        self.assertIn('banner', result)
        self.assertIn(str(self.port.node.ip), result)
        self.assertIn('-sU', result)

    def test_parser_with_banner(self):
        self.port_info()

        result = self.port_info._port

        self.assertEqual(result.service_name, 'ntp')
        self.assertEqual(result.service_version, '1.2.3')

    def test_parser_with_banner_and_without_service(self):
        self.port_info.call = MagicMock(return_value=ElementTree.fromstring(self.XML_BANNER))
        self.port_info()

        result = self.port_info._port

        self.assertEqual(result.service_name, None)
        self.assertEqual(result.service_version, None)
        self.assertEqual(result.banner, r"SSH-1.99-Cisco-1.25")
