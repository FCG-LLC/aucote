import ipaddress
from unittest.mock import MagicMock, patch, call
from xml.etree import ElementTree

from cpe import CPE
from tornado.concurrent import Future
from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit
from structs import Port, TransportProtocol, Node, BroadcastPort, Scan, Vulnerability, VulnerabilityChange, ScanContext, \
    Service

from tools.nmap.tasks.port_info import NmapPortInfoTask
from utils import Config


@patch('scans.task_mapper.TaskMapper', MagicMock)
class NmapPortInfoTaskTest(AsyncTestCase):
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

    XML_CPE = '''<?xml version="1.0" encoding="UTF-8"?>
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
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="60"/><service name="http" product="Apache httpd" version="2.4.23" extrainfo="(Unix)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.23</cpe></service><script id="http-server-header" output="Apache/2.4.23 (Unix)"><elem>Apache/2.4.23 (Unix)</elem>
</script></port>
</ports>
<times srtt="255573" rttvar="196403" to="1041185"/>
</host>
<runstats><finished time="1470733467" timestr="Tue Aug  9 11:04:27 2016" elapsed="1.63" summary="Nmap done at Tue Aug  9 11:04:27 2016; 1 IP address (1 host up) scanned in 1.63 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>'''

    XML_HTTP_WITH_TUNNEL = '''<?xml version="1.0" encoding="UTF-8"?>
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
<ports><port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="253"/><service version="1.2.3" name="http" tunnel="ssl" method="table" conf="3"/></port>
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
        super(NmapPortInfoTaskTest, self).setUp()
        self.aucote = MagicMock()
        self.aucote.task_mapper.assign_tasks = MagicMock(return_value=Future())
        self.aucote.task_mapper.assign_tasks.return_value.set_result(MagicMock())
        self.exploit = Exploit(exploit_id=4)

        self.node = Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1)
        self.node.os = Service(name='os test name', version='os test version',
                               cpe='cpe:2.3:o:vendor:product:-:*:*:*:*:*:*:*')
        self.node_ipv6 = Node(ip=ipaddress.ip_address('::1'), node_id=None)

        self.port = Port(number=22, transport_protocol=TransportProtocol.TCP, node=self.node)
        self.port.scan = Scan()
        self.port_ipv6 = Port(number=22, node=self.node_ipv6, transport_protocol=TransportProtocol.TCP)
        self.scan = Scan()
        self.scanner = MagicMock(NAME='tools')
        self.context = ScanContext(aucote=self.aucote, scan=None)

        self.port_info = NmapPortInfoTask(context=self.context, port=self.port, scan=self.scan, scanner=self.scanner)

        self.cfg = {
            'portdetection': {
                'tools': {
                    'scan_rate': 1337
                },
            },
            'tools': {
                'nmap': {
                    'scripts_dir': 'test'
                }
            }
        }

    @gen_test
    async def test_prepare_args(self):
        self.port_info.store_vulnerability = MagicMock()
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_BANNER))
        self.port_info.command.async_call = MagicMock(return_value=future)
        self.port_info.prepare_args = MagicMock()
        await self.port_info()

        result = self.port_info.command.async_call.call_args[1].get('args', [])
        self.assertEqual(result, self.port_info.prepare_args.return_value)

    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    def test_tcp_scan(self, cfg):
        cfg._cfg = self.cfg
        self.port_info._port.transport_protocol = TransportProtocol.TCP
        result = self.port_info.prepare_args()
        expected = ['-p', '22', '-sV', '-Pn', '--version-all', '--max-rate', '1337', '-sS', '--datadir', 'test',
                    '--script', 'banner', '127.0.0.1']

        self.assertEqual(result, expected)

    def test_init(self):
        self.assertEqual(self.port_info.aucote, self.aucote)

    @patch('tools.nmap.tasks.port_info.Serializer.serialize_vulnerability', MagicMock())
    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    def test_udp_scan(self, cfg):
        self.port_info._port.transport_protocol = TransportProtocol.UDP

        cfg._cfg = self.cfg
        cfg['tools.nmap.scripts_dir'] = ''
        result = self.port_info.prepare_args()
        expected = ['-p', '22', '-sV', '-Pn', '--version-all', '--max-rate', '1337', '-sU', '--script', 'banner',
                    '127.0.0.1']

        self.assertEqual(result, expected)

    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_parser_with_banner(self, cfg):
        self.port_info.store_vulnerability = MagicMock()
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML))
        self.port_info.command.async_call = MagicMock(return_value=future)
        await self.port_info()

        result = self.port_info._port

        self.assertEqual(result.protocol, 'ntp')
        self.assertEqual(result.service.version, '1.2.3')

    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_parser_with_banner_and_without_service(self, cfg):
        self.port_info.store_vulnerability = MagicMock()
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_BANNER))
        self.port_info.command.async_call = MagicMock(return_value=future)
        await self.port_info()

        result = self.port_info._port

        self.assertEqual(result.protocol, None)
        self.assertEqual(result.service.version, None)
        self.assertEqual(result.banner, r"SSH-1.99-Cisco-1.25")

    @gen_test
    async def test_call_broadcast(self):
        self.port_info._port = BroadcastPort()
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_BANNER))
        self.port_info.command.async_call = MagicMock(return_value=future)

        await self.port_info()

        self.aucote.task_mapper.assign_tasks.assert_called_once_with(BroadcastPort())

    @patch('tools.nmap.tasks.port_info.Vulnerability')
    @patch('tools.nmap.tasks.port_info.Serializer.serialize_vulnerability')
    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_add_port_scan_info(self, cfg, mock_serializer, vulnerability):
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_BANNER))
        self.port_info.command.async_call = MagicMock(return_value=future)
        await self.port_info()

        vulnerability.assert_has_calls((call(port=self.port_info._port, context=self.context),))
        mock_serializer.assert_called_once_with(vulnerability.return_value)

        self.port_info.kudu_queue.send_msg.assert_called_once_with(mock_serializer.return_value)

    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    def test_prepare_args_ipv6(self, cfg):
        cfg._cfg = self.cfg
        self.port_info._port = self.port_ipv6

        result = self.port_info.prepare_args()
        expected = '-6'

        self.assertIn(expected, result)

    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_http_with_tunnel(self, cfg):
        self.port_info.store_vulnerability = MagicMock()
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_HTTP_WITH_TUNNEL))
        self.port_info.command.async_call = MagicMock(return_value=future)
        await self.port_info()

        result = self.port_info.store_vulnerability.call_args[0][0].port.protocol
        expected = 'https'

        self.assertEqual(result, expected)

    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_scan_only_true(self, cfg):
        self.port_info.store_vulnerability = MagicMock()
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_HTTP_WITH_TUNNEL))
        self.port_info.command.async_call = MagicMock(return_value=future)
        self.port_info.scan_only = True
        await self.port_info()

        self.assertFalse(self.aucote.task_mapper.assign_tasks.called)

    @patch('tools.nmap.tasks.port_info.TaskMapper')
    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_scan_only_false(self, cfg, task_mapper):
        self.port_info.store_vulnerability = MagicMock()
        cfg._cfg = self.cfg
        self.port_info.scan_only = False
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_HTTP_WITH_TUNNEL))

        task_mapper.return_value.assign_tasks.return_value = Future()
        task_mapper.return_value.assign_tasks.return_value.set_result(True)

        self.port_info.command.async_call = MagicMock(return_value=future)

        await self.port_info()

        self.assertTrue(task_mapper.return_value.assign_tasks.called)

    @gen_test
    async def test_cpe(self):
        self.port_info.store_vulnerability = MagicMock()
        self.port_info.scan_only = True
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_CPE))
        self.port_info.command.async_call = MagicMock(return_value=future)
        self.port_info.prepare_args = MagicMock()
        await self.port_info()

        result = self.port_info.store_vulnerability.call_args[0][0].port.service.cpe
        expected = CPE('cpe:/a:apache:http_server:2.4.23')

        self.assertEqual(result, expected)

    @patch('tools.nmap.tasks.port_info.NmapPortInfoTask.exploit')
    @patch('tools.nmap.tasks.port_info.Vulnerability')
    @patch('tools.nmap.tasks.port_info.cfg', new_callable=Config)
    @gen_test
    async def test_store_vulnerabilities(self, cfg, vulnerability, exploit):
        self.port_info.store_vulnerability = MagicMock()
        cfg._cfg = self.cfg
        future = Future()
        future.set_result(ElementTree.fromstring(self.XML_CPE))
        self.port_info.command.async_call = MagicMock(return_value=future)
        self.port_info.scan_only = True
        await self.port_info()

        expected = 8*[vulnerability.return_value]
        self.aucote.storage.save_vulnerabilities.assert_called_once_with(vulnerabilities=expected,
                                                                         scan=self.port_info._scan)

        vulnerability.assert_has_calls([
            call(exploit=exploit, port=self.port, output='http', subid=vulnerability.SERVICE_PROTOCOL,
                 context=self.context),
            call(exploit=exploit, port=self.port, output='Apache httpd', subid=vulnerability.SERVICE_NAME,
                 context=self.context),
            call(exploit=exploit, port=self.port, output='2.4.23', subid=vulnerability.SERVICE_VERSION,
                 context=self.context),
            call(exploit=exploit, port=self.port, output=None, subid=vulnerability.SERVICE_BANNER,
                 context=self.context),
            call(exploit=exploit, port=self.port, output='cpe:2.3:a:apache:http_server:2.4.23:*:*:*:*:*:*:*',
                 subid=vulnerability.SERVICE_CPE, context=self.context),
            call(exploit=exploit, port=self.port, output='os test name',
                 subid=vulnerability.OS_NAME, context=self.context),
            call(exploit=exploit, port=self.port, output='os test version',
                 subid=vulnerability.OS_VERSION, context=self.context),
            call(exploit=exploit, port=self.port, output='cpe:2.3:o:vendor:product:-:*:*:*:*:*:*:*',
                 subid=vulnerability.OS_CPE, context=self.context)
        ])

    @patch('tools.nmap.tasks.port_info.Serializer.serialize_vulnerability_change')
    @patch('tools.nmap.tasks.port_info.time.time', MagicMock(return_value=12))
    def test_diff_two_last_scans(self, serializer):
        exploit = Exploit(exploit_id=1)
        self.port_info._current_exploits = [self.exploit]
        scan_2 = Scan()
        scans = [self.scan, scan_2]
        self.port_info.storage.get_scans_by_security_scan.return_value = scans
        vuln_added = Vulnerability(port=self.port, exploit=exploit, subid=3, output='a')
        vuln_removed = Vulnerability(port=self.port, exploit=exploit, subid=1, output='b')
        vuln_changed_1 = Vulnerability(port=self.port, exploit=exploit, subid=2, output='c')
        vuln_changed_2 = Vulnerability(port=self.port, exploit=exploit, subid=2, output='d')
        vuln_common = Vulnerability(port=self.port, exploit=exploit, subid=5, output='e')
        self.port_info.storage.get_vulnerabilities.side_effect = ([vuln_added, vuln_changed_1, vuln_common],
                                                                  [vuln_removed, vuln_changed_2, vuln_common])

        expected = [
            VulnerabilityChange(change_time=12, previous_finding=None, current_finding=vuln_added),
            VulnerabilityChange(change_time=12, previous_finding=vuln_removed, current_finding=None),
            VulnerabilityChange(change_time=12, previous_finding=vuln_changed_2, current_finding=vuln_changed_1),
        ]

        self.port_info.diff_with_last_scan()

        self.port_info.storage.get_vulnerabilities.assert_has_calls((
            call(port=self.port, exploit=self.exploit, scan=self.scan),
            call(port=self.port, exploit=self.exploit, scan=scan_2)
        ), any_order=True)

        self.assertCountEqual(self.port_info.storage.save_changes.call_args[0][0], expected)
        serializer.assert_has_calls((call(vuln) for vuln in expected))

    @patch('tools.nmap.tasks.port_info.Serializer.serialize_vulnerability_change')
    @patch('tools.nmap.tasks.port_info.time.time', MagicMock(return_value=12))
    def test_diff_two_last_scans_first_scan(self, serializer):
        exploit = Exploit(exploit_id=1)
        self.port_info._current_exploits = [self.exploit]
        scans = [self.scan]
        self.port_info.storage.get_scans_by_security_scan.return_value = scans
        vuln_added = Vulnerability(port=self.port, exploit=exploit, subid=3, output='a')
        vuln_changed_1 = Vulnerability(port=self.port, exploit=exploit, subid=2, output='c')
        self.port_info.storage.get_vulnerabilities.return_value = [vuln_added, vuln_changed_1]

        expected = [
            VulnerabilityChange(change_time=12, previous_finding=None, current_finding=vuln_added),
            VulnerabilityChange(change_time=12, previous_finding=None, current_finding=vuln_changed_1)
        ]

        self.port_info.diff_with_last_scan()

        self.port_info.storage.get_vulnerabilities.assert_has_calls((
            call(port=self.port, exploit=self.exploit, scan=self.scan),
        ))

        self.assertCountEqual(self.port_info.storage.save_changes.call_args[0][0], expected)
        serializer.assert_has_calls((call(vuln) for vuln in expected), any_order=True)
