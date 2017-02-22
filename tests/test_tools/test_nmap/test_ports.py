import ipaddress
from unittest import TestCase
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from structs import Node, Scan
from tools.nmap.ports import PortsScan
from utils import Config


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

    NON_XML = b'''This is non xml output!'''

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def setUp(self, cfg):
        cfg._cfg = {
            'service': {
                'scans': {
                    'ports': '80',
                    'rate': 1000
                }
            },
            'tools': {
                'nmap': {
                    'cmd': 'nmap'
                }
            }
        }
        self.cfg = cfg
        self.kudu_queue = MagicMock()
        self.scanner = PortsScan(ipv6=True, tcp=False, udp=False)
        node = Node(ip=ipaddress.ip_address('192.168.1.5'), node_id=None)
        node.scan = Scan()
        self.nodes = [node]

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments(self, mock_config):
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': 'T:17-45'
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                },
                'nmap': {
                    'scripts_dir': 'test'
                }
            },
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '--script', 'banner', '-6', '--datadir', 'test', '-p', 'T:17-45', '--max-rate', '1000',
                    '192.168.1.5']

        self.assertEqual(result, expected)

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments_tcp(self, mock_config):
        self.scanner.tcp = True
        self.scanner.ipv6 = False
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': 'T:17-45'
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                },
                'nmap': {
                    'scripts_dir': 'test'
                }
            },
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '--script', 'banner', '-sS', '--datadir', 'test', '-p', 'T:17-45', '--max-rate', '1000',
                    '192.168.1.5']

        self.assertEqual(result, expected)

    @patch('tools.nmap.ports.cfg', new_callable=Config)
    def test_arguments_udp(self, mock_config):
        self.scanner.udp = True
        self.scanner.ipv6 = False
        mock_config._cfg = {
            'service': {
                'scans': {
                    'network_scan_rate': '1000',
                    'ports': 'T:17-45'
                }
            },
            'tools': {
                'masscan': {
                    'args': [
                        'arg1', 'arg2', 'test'
                    ]
                },
                'nmap': {
                    'scripts_dir': 'test'
                }
            },
        }

        result = self.scanner.prepare_args(self.nodes)
        expected = ['-sV', '--script', 'banner', '-sU', '--datadir', 'test', '-p', 'T:17-45', '--max-rate', '1000',
                    '192.168.1.5']

        self.assertEqual(result, expected)