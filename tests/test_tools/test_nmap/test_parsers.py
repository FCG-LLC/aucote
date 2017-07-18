from unittest import TestCase
from unittest.mock import MagicMock
from xml.etree import ElementTree

from tools.nmap.parsers import NmapBrutParser, NmapVulnParser, NmapParser, NmapInfoParser


class NmapBrutParserTest(TestCase):
    VALID_ACCOUNTS = """<script id="ipmi-dumphashes" output="&#xa;  Accounts: &#xa;    admin:ada660f4b4597d53ac7013097e1ebe35f827064d - 4f4c584b840100005445534348554342454e5a4d4245574619fbaa65116404553b1a5ae23427ec18a123456789abcdefa123456789abcdef140561646d696e&#xa;    cirros:88280602cf8972d09e5c8f38a527e8625d8dc1ce - 505547538a06000049545659554a4959584457564246574a04e57a122a7cdb5052815c575e9ca045a123456789abcdefa123456789abcdef1406636972726f73&#xa;    &lt;empty&gt;:&lt;empty&gt; - Valid credentials&#xa;  Statistics: Performed 12 guesses in 1 seconds, average tps: 12.0"><table key="Accounts">
<table>
<elem key="username">admin</elem>
<elem key="state">4f4c584b840100005445534348554342454e5a4d4245574619fbaa65116404553b1a5ae23427ec18a123456789abcdefa123456789abcdef140561646d696e</elem>
<elem key="password">ada660f4b4597d53ac7013097e1ebe35f827064d</elem>
</table>
<table>
<elem key="username">cirros</elem>
<elem key="state">505547538a06000049545659554a4959584457564246574a04e57a122a7cdb5052815c575e9ca045a123456789abcdefa123456789abcdef1406636972726f73</elem>
<elem key="password">88280602cf8972d09e5c8f38a527e8625d8dc1ce</elem>
</table>
<table>
<elem key="username">&lt;empty&gt;</elem>
<elem key="state">Valid credentials</elem>
<elem key="password">&lt;empty&gt;</elem>
</table>
</table>
<elem key="Statistics">Performed 12 guesses in 1 seconds, average tps: 12.0</elem>
</script>"""

    NO_VALID_ACCOUNTS = """<script id="ipmi-dumphashes" output="&#xa;  Accounts: No valid accounts found&#xa;  Statistics: Performed 1 guesses in 1 seconds, average tps: 1.0"><elem key="Accounts">No valid accounts found</elem>
<elem key="Statistics">Performed 1 guesses in 1 seconds, average tps: 1.0</elem>
</script>"""

    NO_TABLE_OUTPUT = """<script id="ipmi-dumphashes" output="Statistics: Performed 1 guesses in 1 seconds, average tps: 1.0"><elem key="Accounts">No valid accounts found</elem>
<elem key="Statistics">Performed 1 guesses in 1 seconds, average tps: 1.0</elem>
</script>"""

    def setUp(self):
        self.parser = NmapBrutParser()

    def test_valid_accounts(self):
        script = ElementTree.fromstring(self.VALID_ACCOUNTS)
        result = self.parser.parse(script)
        expected = """Accounts:
<empty>:<empty>

Hashes:
admin:ada660f4b4597d53ac7013097e1ebe35f827064d:4f4c584b840100005445534348554342454e5a4d4245574619fbaa65116404553b1a5ae23427ec18a123456789abcdefa123456789abcdef140561646d696e
cirros:88280602cf8972d09e5c8f38a527e8625d8dc1ce:505547538a06000049545659554a4959584457564246574a04e57a122a7cdb5052815c575e9ca045a123456789abcdefa123456789abcdef1406636972726f73"""
        self.assertEqual(result, expected)

    def test_no_valid_accounts(self):
        script = ElementTree.fromstring(self.NO_VALID_ACCOUNTS)
        result = self.parser.parse(script)
        self.assertIsNone(result)

    def test_no_data(self):
        self.assertIsNone(self.parser.parse(None))

    def test_no_table_output(self):
        script = ElementTree.fromstring(self.NO_TABLE_OUTPUT)
        result = self.parser.parse(script)
        self.assertIsNone(result)


class NmapVulnParserTest(TestCase):
    VULN_OUTPUT = """<script id="ipmi-cipher-zero" output="test_output"><table key="NMAP-1">
<elem key="title">IPMI 2.0 RAKP Cipher Zero Authentication Bypass</elem>
<elem key="state">VULNERABLE</elem>
<table key="description">
<elem>&#xa;The issue is due to the vendor shipping their devices with the&#xa;cipher suite &apos;0&apos; (aka &apos;cipher zero&apos;) enabled. This allows a&#xa;remote attacker to authenticate to the IPMI interface using&#xa;an arbitrary password. The only information required is a valid&#xa;account, but most vendors ship with a default &apos;admin&apos; account.&#xa;This would allow an attacker to have full control over the IPMI&#xa;functionality&#xa;    </elem>
</table>
</table>
</script>"""

    VULN_OUTPUT_LIKELY_VULNERABLE = """<script id="ipmi-cipher-zero" output="test_output"><table key="NMAP-1">
<elem key="title">IPMI 2.0 RAKP Cipher Zero Authentication Bypass</elem>
<elem key="state">LIKELY VULNERABLE</elem>
<table key="description">
<elem>&#xa;The issue is due to the vendor shipping their devices with the&#xa;cipher suite &apos;0&apos; (aka &apos;cipher zero&apos;) enabled. This allows a&#xa;remote attacker to authenticate to the IPMI interface using&#xa;an arbitrary password. The only information required is a valid&#xa;account, but most vendors ship with a default &apos;admin&apos; account.&#xa;This would allow an attacker to have full control over the IPMI&#xa;functionality&#xa;    </elem>
</table>
</table>
</script>"""

    VULN_OUTPUT_VULNERABLE_DOS = """<script id="ipmi-cipher-zero" output="test_output"><table key="NMAP-1">
<elem key="title">IPMI 2.0 RAKP Cipher Zero Authentication Bypass</elem>
<elem key="state">VULNERABLE (DoS)</elem>
<table key="description">
<elem>&#xa;The issue is due to the vendor shipping their devices with the&#xa;cipher suite &apos;0&apos; (aka &apos;cipher zero&apos;) enabled. This allows a&#xa;remote attacker to authenticate to the IPMI interface using&#xa;an arbitrary password. The only information required is a valid&#xa;account, but most vendors ship with a default &apos;admin&apos; account.&#xa;This would allow an attacker to have full control over the IPMI&#xa;functionality&#xa;    </elem>
</table>
</table>
</script>"""

    VULN_OUTPUT_VULNERABLE_EXPLOITABLE = """<script id="ipmi-cipher-zero" output="test_output"><table key="NMAP-1">
<elem key="title">IPMI 2.0 RAKP Cipher Zero Authentication Bypass</elem>
<elem key="state">VULNERABLE (Exploitable)</elem>
<table key="description">
<elem>&#xa;The issue is due to the vendor shipping their devices with the&#xa;cipher suite &apos;0&apos; (aka &apos;cipher zero&apos;) enabled. This allows a&#xa;remote attacker to authenticate to the IPMI interface using&#xa;an arbitrary password. The only information required is a valid&#xa;account, but most vendors ship with a default &apos;admin&apos; account.&#xa;This would allow an attacker to have full control over the IPMI&#xa;functionality&#xa;    </elem>
</table>
</table>
</script>"""

    NON_VULN_OUTPUT = """<script id="ipmi-cipher-zero" output="test_output"><table key="NMAP-1">
<elem key="title">IPMI 2.0 RAKP Cipher Zero Authentication Bypass</elem>
<elem key="state">NON VULNERABLE</elem>
<table key="description">
<elem>&#xa;The issue is due to the vendor shipping their devices with the&#xa;cipher suite &apos;0&apos; (aka &apos;cipher zero&apos;) enabled. This allows a&#xa;remote attacker to authenticate to the IPMI interface using&#xa;an arbitrary password. The only information required is a valid&#xa;account, but most vendors ship with a default &apos;admin&apos; account.&#xa;This would allow an attacker to have full control over the IPMI&#xa;functionality&#xa;    </elem>
</table>
</table>
</script>"""

    def setUp(self):
        self.parser = NmapVulnParser()

    def test_no_data(self):
        self.assertIsNone(self.parser.parse(None))

    def test_vulnerable(self):
        script = ElementTree.fromstring(self.VULN_OUTPUT)
        result = self.parser.parse(script)
        expected = 'test_output'
        self.assertEqual(result, expected)

    def test_likely_vulnerable(self):
        script = ElementTree.fromstring(self.VULN_OUTPUT_LIKELY_VULNERABLE)
        result = self.parser.parse(script)
        expected = 'test_output'
        self.assertEqual(result, expected)

    def test_vulnerable_dos(self):
        script = ElementTree.fromstring(self.VULN_OUTPUT_VULNERABLE_DOS)
        result = self.parser.parse(script)
        expected = 'test_output'
        self.assertEqual(result, expected)

    def test_vulnerable_exploitable(self):
        script = ElementTree.fromstring(self.VULN_OUTPUT_VULNERABLE_EXPLOITABLE)
        result = self.parser.parse(script)
        expected = 'test_output'
        self.assertEqual(result, expected)

    def test_non_vulnerable(self):
        script = ElementTree.fromstring(self.NON_VULN_OUTPUT)
        result = self.parser.parse(script)
        self.assertIsNone(result)


class NmapInfoParserTest(TestCase):
    VALID_OUTPUT = """<script output="test_output">
</script>
"""
    EMPTY_OUTPUT = """<script output="&#xa;">
</script>
"""

    ERROR_OUTPUT = """<script output="ERROR: test_output">
</script>
"""

    def setUp(self):
        self.parser = NmapInfoParser()

    def test_no_data(self):
        self.assertIsNone(self.parser.parse(None))

    def test_error_output(self):
        script = ElementTree.fromstring(self.ERROR_OUTPUT)
        result = self.parser.parse(script)
        self.assertIsNone(result)

    def test_valid_output(self):
        script = ElementTree.fromstring(self.VALID_OUTPUT)
        result = self.parser.parse(script)
        expected = 'test_output'
        self.assertEqual(result, expected)

    def test_empty_output(self):
        script = ElementTree.fromstring(self.EMPTY_OUTPUT)
        result = self.parser.parse(script)
        self.assertIsNone(result)


class NmapParserTest(TestCase):
    def setUp(self):
        self.parser = NmapParser()

    def test_parse_implemented(self):
        script = MagicMock()
        self.assertRaises(NotImplementedError, self.parser.parse, script)
