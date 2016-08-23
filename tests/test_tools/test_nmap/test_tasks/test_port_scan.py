import unittest
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from database.serializer import Serializer
from fixtures.exploits import Exploit
from fixtures.exploits import Exploits
from structs import Port, TransportProtocol, Node, Vulnerability
from tools.nmap.base import NmapScript, InfoNmapScript, VulnNmapScript

# TODO: This tests are complicated because of nesting and many mocking. Should be refactored.
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

    def setUp(self):
        """
        Prepare some internal variables:
            exploit, port, exploits, script, vulnerability, scan_task
        """
        self.executor = MagicMock()

        self.exploit = Exploit()
        self.exploit.app = 'nmap'
        self.exploit.name = 'test'

        self.exploit_vuln_non_exist = Exploit()
        self.exploit_vuln_non_exist.app = 'nmap'
        self.exploit_vuln_non_exist.name = 'test2'

        self.exploits = Exploits()
        self.exploits.add(self.exploit)

        self.port = Port()
        self.port.node = Node()
        self.port.node.ip = '127.0.0.1'

        self.script = InfoNmapScript(port=self.port, exploit=self.exploit, name='test', args='test_args')
        self.script2 = VulnNmapScript(port=self.port, exploit=self.exploit_vuln_non_exist, name='test2',
                                      args='test_args')

        self.vulnerability = Vulnerability()
        self.script.get_vulnerability = MagicMock(return_value=self.vulnerability)

        self.port.transport_protocol = TransportProtocol.TCP
        self.port.number = 22
        self.port.service_name = 'ssh'

        self.scan_task = NmapPortScanTask(executor=self.executor, port=self.port,
                                          script_classes=[self.script, self.script2])

    def test_init(self):
        self.assertEqual(self.scan_task.executor, self.executor)
        self.assertEqual(self.scan_task.port, self.port)
        self.assertEqual(self.scan_task.script_classes, [self.script, self.script2])

    def test_tcp_scan(self):
        """
        Test TCP scanning
        """
        self.scan_task.call = MagicMock(side_effect=self.check_args_tcp)
        self.scan_task()

    def check_args_tcp(self, args):
        """
        Check if script is executing with proper arguments
        """
        self.assertIn('-p', args)
        self.assertIn('22', args)
        self.assertIn('-sV', args)
        self.assertIn('--script', args)
        self.assertIn(self.script.name, args)
        self.assertIn('--script-args', args)
        self.assertIn(self.script.args, args)
        self.assertIn(self.port.node.ip, args)

        return ElementTree.fromstring(self.XML)

    def test_udp_scan(self):
        """
        Test UDP scanning
        """
        self.scan_task._port.transport_protocol = TransportProtocol.UDP
        self.scan_task.call = MagicMock(side_effect=self.check_args_udp)
        self.scan_task()

    def check_args_udp(self, args):
        """
        Check if script is executing with proper arguments
        """
        self.assertIn('-sU', args)
        return self.check_args_tcp(args)

    def test_no_vulnerabilities(self):
        scan_task = NmapPortScanTask(port=self.port, script_classes=[], executor=self.executor)
        scan_task.call = MagicMock(return_value=ElementTree.fromstring(self.NO_VULNERABILITIES_XML))
        scan_task()

        scan_task.kudu_queue.send_msg.assert_called_once_with('test')
