import ipaddress
import unittest
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from fixtures.exploits import Exploit
from fixtures.exploits import Exploits
from structs import Port, TransportProtocol, Node, Vulnerability, Scan
from tools.nmap.base import InfoNmapScript, VulnNmapScript

from tools.nmap.tasks.port_scan import NmapPortScanTask


@patch('database.serializer.Serializer.serialize_port_vuln', MagicMock(return_value='test'))
class NmapPortScanTaskTest(unittest.TestCase):
    """
    Testing nmap port scanning task

    """
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
<ports>
<port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="253"/>
<script id="test" output="VUNERABLE: SSH-1.99-Cisco-1.25"/>
<script id="test2" output="VUNERABLE: SSH-1.99-Cisco-1.25"/>
<script id="test3" output="VUNERABLE: SSH-1.99-Cisco-1.25"/>
</port>
</ports>
<times srtt="255573" rttvar="196403" to="1041185"/>
</host>
<runstats><finished time="1470733467" timestr="Tue Aug  9 11:04:27 2016" elapsed="1.63" summary="Nmap done at Tue Aug  9 11:04:27 2016; 1 IP address (1 host up) scanned in 1.63 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    NO_VULNERABILITIES_XML = '''<?xml version="1.0" encoding="UTF-8"?>
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
<ports><port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="253"/></port>
</ports>
<times srtt="255573" rttvar="196403" to="1041185"/>
</host>
<runstats><finished time="1470733467" timestr="Tue Aug  9 11:04:27 2016" elapsed="1.63" summary="Nmap done at Tue Aug  9 11:04:27 2016; 1 IP address (1 host up) scanned in 1.63 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    PRESCRIPT_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.12 scan initiated Tue Aug  9 11:04:25 2016 as: nmap -oX - -sU -p 123 -&#45;script banner 192.168.2.1 -->
<nmaprun scanner="nmap" args="nmap -oX - -sU -p 123 -&#45;script banner 192.168.2.1" start="1470733465" startstr="Tue Aug  9 11:04:25 2016" version="7.12" xmloutputversion="1.04">
<scaninfo type="udp" protocol="udp" numservices="1" services="123"/>
<verbose level="0"/>
<debugging level="0"/>
<prescript><script id="test" output="test" /></prescript>
<host starttime="1470733466" endtime="1470733467"><status state="up" reason="echo-reply" reason_ttl="253"/>
<address addr="192.168.2.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="253"/></port>
</ports>
<times srtt="255573" rttvar="196403" to="1041185"/>
</host>
<runstats><finished time="1470733467" timestr="Tue Aug  9 11:04:27 2016" elapsed="1.63" summary="Nmap done at Tue Aug  9 11:04:27 2016; 1 IP address (1 host up) scanned in 1.63 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    def setUp(self):
        """
        Prepare some internal variables:
            exploit, port, exploits, script, vulnerability, scan_task

        """
        self.executor = MagicMock()

        self.exploit = Exploit(exploit_id=1, app='nmap', name='test')
        self.exploit_vuln_non_exist = Exploit(exploit_id=2, app='nmap', name='test2')
        self.exploits = Exploits()
        self.exploits.add(self.exploit)

        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=None)

        self.port = Port(number=22, node=self.node, transport_protocol=TransportProtocol.TCP)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()

        self.script = InfoNmapScript(port=self.port, exploit=self.exploit, name='test', args='test_args')
        self.script.get_result = MagicMock(return_value='test')
        self.script2 = VulnNmapScript(port=self.port, exploit=self.exploit_vuln_non_exist, name='test2',
                                      args='test_args')
        self.scan_task = NmapPortScanTask(executor=self.executor, port=self.port,
                                          script_classes=[self.script, self.script2])
        self.scan_task.store_scan_end = MagicMock()

        self.scan_task.command.call = MagicMock()
        self.scan_task.command.call.return_value = ElementTree.fromstring(self.XML)

    def test_init(self):
        self.assertEqual(self.scan_task.executor, self.executor)
        self.assertEqual(self.scan_task.port, self.port)
        self.assertEqual(self.scan_task.script_classes, [self.script, self.script2])

    def test_tcp_scan(self):
        """
        Test TCP scanning

        """
        self.scan_task()

        result = self.scan_task.command.call.call_args[0][0]

        self.assertIn('-sV', result)
        self.assertIn('--script', result)
        self.assertIn(self.script.name, result)
        self.assertIn('--script-args', result)
        self.assertIn(self.script.args, result)
        self.assertIn(str(self.port.node.ip), result)
        self.assertIn('-p', result)
        self.assertIn('22', result)

    def test_udp_scan(self):
        """
        Test UDP scanning

        """
        self.scan_task._port.transport_protocol = TransportProtocol.UDP
        self.scan_task()

        result = self.scan_task.command.call.call_args[0][0]

        self.assertIn('-sV', result)
        self.assertIn('--script', result)
        self.assertIn(self.script.name, result)
        self.assertIn('--script-args', result)
        self.assertIn(self.script.args, result)
        self.assertIn(str(self.port.node.ip), result)
        self.assertIn('-p', result)
        self.assertIn('22', result)
        self.assertIn('-sU', result)

    @patch('tools.nmap.tasks.port_scan.Vulnerability')
    def test_prescript(self, mock_vulnerability):
        self.scan_task.command.call = MagicMock(return_value=ElementTree.fromstring(self.PRESCRIPT_XML))
        self.scan_task()

        expected = 'test'
        result = mock_vulnerability.call_args[1]['output']

        self.assertEqual(result, expected)

    def test_dns_scan(self):
        """
        Test UDP scanning

        """
        self.port.number = 53
        self.scan_task()

        result = self.scan_task.command.call.call_args[0][0]
        self.assertIn('-p', result)
        self.assertIn('53', result)
        self.assertIn('--dns-servers', result)

    @patch('time.time', MagicMock(return_value=27.0))
    @patch('tools.nmap.tasks.port_scan.Vulnerability', MagicMock())
    def test_storage(self):
        self.scan_task.command.call = MagicMock(return_value=ElementTree.fromstring(self.PRESCRIPT_XML))
        self.scan_task()

        result = self.scan_task.store_scan_end.call_args[1]
        expected = {
            'exploits': [self.script.exploit, self.script2.exploit],
            'port': self.port,
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(self.port.scan.end, 27.0)

    def test_prepare_args(self):
        self.scan_task._port = Port.broadcast()

        result = self.scan_task.prepare_args()
        expected = ['--script', 'test', '--script', 'test2']

        self.assertCountEqual(result, expected)
