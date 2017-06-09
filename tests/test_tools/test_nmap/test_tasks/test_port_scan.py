import ipaddress
import unittest
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from tornado.concurrent import Future
from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from fixtures.exploits import Exploits
from structs import Port, TransportProtocol, Node, Scan, PhysicalPort, BroadcastPort

from tools.nmap.tasks.port_scan import NmapPortScanTask
from utils import Config
from tools.nmap.parsers import NmapParser, NmapInfoParser
from tools.nmap.base import NmapScript


@patch('database.serializer.Serializer.serialize_port_vuln', MagicMock(return_value='test'))
class NmapPortScanTaskTest(AsyncTestCase):
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
<script id="test2" output="ERROR: VUNERABLE: SSH-1.99-Cisco-1.25"/>
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

    HOSTSCRIPT_XML = '''<?xml version="1.0" encoding="UTF-8"?>
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
<hostscript><script id="test" output="test_hostscript" /></hostscript>
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
        super(NmapPortScanTaskTest, self).setUp()
        self.aucote = MagicMock()

        self.exploit = Exploit(exploit_id=1, app='nmap', name='test')
        self.exploit_vuln_non_exist = Exploit(exploit_id=2, app='nmap', name='test2')
        self.exploits = Exploits()
        self.exploits.add(self.exploit)

        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=None)
        self.node_ipv6 = Node(ip=ipaddress.ip_address('::1'), node_id=None)

        self.port = Port(number=22, node=self.node, transport_protocol=TransportProtocol.TCP)
        self.port.service_name = 'ssh'
        self.port.scan = Scan()

        self.port_ipv6 = Port(number=22, node=self.node_ipv6, transport_protocol=TransportProtocol.TCP)

        self.script = NmapScript(port=self.port, parser=NmapParser(), exploit=self.exploit, name='test', args='test_args')
        self.script.get_result = MagicMock(return_value='test')
        self.script2 = NmapScript(port=self.port, parser=NmapInfoParser(), exploit=self.exploit_vuln_non_exist, name='test2')
        self.scan_task = NmapPortScanTask(aucote=self.aucote, port=self.port,
                                          script_classes=[self.script, self.script2], rate=1337)
        self.scan_task.store_scan_end = MagicMock()

        future = Future()
        future.set_result(ElementTree.fromstring(self.XML))
        self.scan_task.command.async_call = MagicMock(return_value=future)

        self.cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': ''
                }
            }
        }

    def test_init(self):
        self.assertEqual(self.scan_task.aucote, self.aucote)
        self.assertEqual(self.scan_task.port, self.port)
        self.assertEqual(self.scan_task.script_classes, [self.script, self.script2])

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_tcp_scan(self, cfg):
        """
        Test TCP scanning

        """
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': ''
                }
            }
        }
        self.scan_task()

        result = set(self.scan_task.prepare_args())
        expected = {'--max-rate', '1337', '-p', '22', '--script', '--script-args', 'test_args',
                    '127.0.0.1'}

        self.assertTrue(expected.issubset(result))
        self.assertTrue('test,test2' in result or 'test2,test' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_tcp_scan_service_detection(self, cfg):
        """
        Test TCP scanning

        """
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': ''
                }
            }
        }
        self.scan_task()

        result = set(self.scan_task.prepare_args())
        expected = {'-sV'}

        self.assertTrue(expected.issubset(result))
        self.assertTrue('test,test2' in result or 'test2,test' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_udp_scan(self, cfg):
        """
        Test UDP scanning

        """
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': ''
                }
            }
        }
        self.scan_task._port.transport_protocol = TransportProtocol.UDP
        self.scan_task()

        result = set(self.scan_task.prepare_args())
        expected = {'--max-rate', '1337', '-p', '22', '-sU', '--script', '--script-args', 'test_args',
                    '127.0.0.1'}

        self.assertTrue(expected.issubset(result))
        self.assertTrue('test,test2' in result or 'test2,test' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_no_vulnerabilities(self, cfg):
        cfg._cfg = self.cfg
        self.scan_task.command.call = MagicMock(return_value=ElementTree.fromstring(self.NO_VULNERABILITIES_XML))
        self.scan_task()

        self.assertFalse(self.scan_task.kudu_queue.send_msg.called)

    @patch('tools.nmap.tasks.port_scan.Vulnerability')
    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    @gen_test
    async def test_prescript(self, cfg, mock_vulnerability):
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.PRESCRIPT_XML))
        self.scan_task.command.async_call = MagicMock(return_value=future)
        await self.scan_task()

        expected = 'test'
        result = mock_vulnerability.call_args[1]['output']

        self.assertEqual(result, expected)

    @patch('tools.nmap.tasks.port_scan.Vulnerability')
    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    @gen_test
    async def test_hostscript(self, cfg, mock_vulnerability):
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.HOSTSCRIPT_XML))
        self.scan_task.command.async_call = MagicMock(return_value=future)
        await self.scan_task()

        expected = 'test'
        result = mock_vulnerability.call_args[1]['output']

        self.assertEqual(result, expected)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    @gen_test
    async def test_dns_scan(self, cfg):
        """
        Test UDP scanning

        """
        cfg._cfg = self.cfg
        self.scan_task._port.number = 53
        await self.scan_task()

        result = self.scan_task.command.async_call.call_args[0][0]
        self.assertIn('-p', result)
        self.assertIn('53', result)
        self.assertIn('--dns-servers', result)

    @patch('time.time', MagicMock(return_value=27.0))
    @patch('tools.nmap.tasks.port_scan.Vulnerability', MagicMock())
    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    @gen_test
    async def test_storage(self, cfg):
        cfg._cfg = self.cfg
        self.scan_task._script_classes = [self.script]
        future = Future()
        future.set_result(ElementTree.fromstring(self.PRESCRIPT_XML))
        self.scan_task.command.async_call = MagicMock(return_value=future)
        await self.scan_task()

        result = self.scan_task.store_scan_end.call_args[1]
        expected = {
            'exploits': [self.script.exploit, self.script2.exploit],
            'port': self.port,
        }

        self.assertDictEqual(result, expected)
        self.assertEqual(self.port.scan.end, 27.0)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_prepare_args_broadcast(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': ''
                }
            }
        }
        self.scan_task._port = BroadcastPort()

        result = set(self.scan_task.prepare_args())
        expected = {'--max-rate', '1337', '--script', '--script-args', 'test_args'}

        self.assertTrue(expected.issubset(result))
        self.assertTrue('test,test2' in result or 'test2,test' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_prepare_args_physical(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': ''
                }
            }
        }
        self.scan_task._port = PhysicalPort()
        self.scan_task._port.interface = 'wlan0'

        result = set(self.scan_task.prepare_args())
        expected = {'--max-rate', '1337', '--script', '--script-args', 'test_args', '-e', 'wlan0'}

        self.assertTrue(expected.issubset(result))
        self.assertTrue('test,test2' in result or 'test2,test' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_prepare_args_ipv6(self, cfg):
        cfg._cfg = self.cfg
        self.scan_task._port = self.port_ipv6

        result = self.scan_task.prepare_args()
        expected = '-6'

        self.assertIn(expected, result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_prepare_args_scripts_dir(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': './test_dir/'
                }
            }
        }
        self.scan_task._port = PhysicalPort()
        self.scan_task._port.interface = 'wlan0'

        result = set(self.scan_task.prepare_args())
        expected = {'--max-rate', '1337', '--datadir', './test_dir/', '--script', '--script-args',
                    'test_args', '-e', 'wlan0'}

        self.assertTrue(expected.issubset(result))
        self.assertTrue('test,test2' in result or 'test2,test' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_prepare_args_scripts_args(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': './test_dir/'
                }
            }
        }
        self.script2.args = 'other_args'
        self.scan_task._port = PhysicalPort()
        self.scan_task._port.interface = 'wlan0'

        result = set(self.scan_task.prepare_args())

        self.assertTrue('test_args,other_args' in result or 'other_args,test_args' in result)

    @patch('tools.nmap.tasks.port_scan.cfg', new_callable=Config)
    def test_prepare_no_args(self, cfg):
        cfg._cfg = {
            'tools': {
                'nmap': {
                    'scripts_dir': './test_dir/'
                }
            }
        }
        self.script.args = ''

        result = set(self.scan_task.prepare_args())

        self.assertNotIn('--script-args', result)
