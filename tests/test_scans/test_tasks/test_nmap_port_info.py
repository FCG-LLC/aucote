import unittest
from unittest.mock import MagicMock, patch, Mock
from xml.etree import ElementTree

from scans.tasks import NmapPortInfoTask
from structs import Port, TransportProtocol, Node


# TODO: This tests are complicated because of nesting and many mocking. Should be refactored.
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

    def setUp(self):
        self.port = Port()
        self.port.node = Node()
        self.port.node.ip = '127.0.0.1'
        self.port.number = '22'

        self.port.transport_protocol = TransportProtocol.from_nmap_name("TCP")

        self.port_info = NmapPortInfoTask(self.port)
        self.port_info.call = MagicMock(return_value=ElementTree.fromstring(self.XML))
        self.port_info.executor = Mock()

    def test_tcp_scan(self):
        self.port_info.call = MagicMock(side_effect=self.check_args_tcp)
        self.port_info()

    def check_args_tcp(self, args):
        self.assertIn('-p', args)
        self.assertIn('22', args)
        self.assertIn('-sV', args)
        self.assertIn('--script', args)
        self.assertIn('banner', args)
        self.assertIn(self.port.node.ip, args)

        return ElementTree.fromstring(self.XML)

    def test_udp_scan(self):
        self.port_info._port.transport_protocol = TransportProtocol.from_nmap_name("UDP")
        self.port_info.call = MagicMock(side_effect=self.check_args_udp)
        self.port_info()

    def check_args_udp(self, args):
        self.assertIn('-sU', args)
        return self.check_args_tcp(args)

    def test_parser(self):
        self.port_info()

        self.assertEqual(self.port_info._port.service_name, 'ntp')
        self.assertEqual(self.port_info._port.service_version, '1.2.3')
