"""
This file provides structures for project.

"""
import ipaddress
import re
from enum import Enum
import time
from threading import Semaphore

from cpe import CPE


class Scan(object):
    """
    Scan object

    """

    def __init__(self, start=None, end=None):
        """
        Args:
            start (int|float): start scan time
            end (int|float): end scan time

        """
        self._start = start
        self.end = end

    @property
    def start(self):
        """
        Time, when scan start

        Returns:
            int - timestamp
        """
        return self._start


class Node:
    """
    Node object consist of name, id and ip

    """

    def __init__(self, node_id, ip):
        """
        Init values
        Args:
            node_id (int):
            ip (IPv4Address):

        """
        self.name = None
        self.ip = ip
        self.id = node_id
        self.scan = None
        self.os = Service()

    def __eq__(self, other):
        return isinstance(other, Node) and self.ip == other.ip and self.id == other.id

    def __ne__(self, other):
        return (not isinstance(other, Node)) or self.ip != other.ip or self.id != other.id

    def __hash__(self):
        return hash((self.id, self.ip))

    @property
    def is_ipv6(self):
        """
        Returns True if node is using ipv6 addressing

        Returns:
            bool

        """
        return isinstance(self.ip, ipaddress.IPv6Address)

    def __str__(self):
        """
        Returns string representation of node

        Returns:
            str
        """
        return "{0}[{1}]".format(self.ip, self.id)

    def __repr__(self):
        """
        Returns representation of object

        Returns:
            str
        """
        return "<{id}, {ip}>".format(id=self.id, ip=self.ip)


class TransportProtocol(Enum):
    """
    Transport protocol object consist of db_val and IANA val

    """

    def __init__(self, db_val, iana):
        self.db_val = db_val
        self.iana = iana

    ICMP = ('ICMP', 1)
    TCP = ('TCP', 6)
    UDP = ('UDP', 17)
    SCTP = ('SCTP', 132)
    PHY = ('PHY', 255)

    @classmethod
    def from_nmap_name(cls, name):
        """
        Create TransportProtocol object basing on string name

        Args:
            name (str): string representation of transport protocol, eg. "tcp", "udp"

        Returns:
            TransportProtocol object

        Raises:
            ValueError if not: tcp, udp or icmp

        """
        name = name.upper()
        for val in cls:
            if val.db_val == name:
                return val
        raise ValueError('Invalid transport protocol name: %s' % name)

    @classmethod
    def from_iana(cls, number):
        """
        Create TransportProtocol object basing on protocol number

        Args:
            number (int): protocol number

        Returns:
            TransportProtocol

        """
        for val in cls:
            if val.iana == number:
                return val
        raise ValueError('Invalid transport protocol number: %s' % number)


class RiskLevel(Enum):
    """
    Risk level object

    """

    def __init__(self, txt, number):
        self.txt = txt
        self.number = number

    HIGH = ('High', 3)
    MEDIUM = ('Medium', 2)
    LOW = ('Low', 1)
    NONE = ('None', 0)

    @classmethod
    def from_name(cls, name):
        """
        Create RiskLevel object basing on string name

        Args:
            name: string representation of risk level, eg. "medium"

        Returns:
            RiskLevel object

        Raises:
            ValueError if not: High, Medium, Low or None

        """
        for val in cls:
            if val.txt == name:
                return val
        raise ValueError('Unsupported risk level name: %s' % name)


class Service(object):
    """
    Represents service/application/operating system. Contains basic information: name, version

    """
    _CPE_SPECIAL = r"\!|\"|\;|\#|\$|\%|\&|\'|\(|\)|\+|\,|\/|\:|\<|\=|\>|\@|\[|\]|\^|\`|\{|\||\}|\~|\-"
    _ESCAPE_CPE = re.compile(_CPE_SPECIAL)
    _UNESCAPE_CPE = re.compile(r"(\\({0}))".format(_CPE_SPECIAL))

    def __init__(self, name=None, version=None):
        self.name = name
        self.version = version
        self._cpe = None

    @property
    def cpe(self):
        """
        CPE representation of service

        Returns:
            CPE

        """
        return self._cpe

    @cpe.setter
    def cpe(self, value):
        if value:
            self._cpe = CPE(value)

    @property
    def cpe_vendor(self):
        """
        Get vendor name based on CPE

        Returns:
            str|None

        """
        if isinstance(self._cpe, CPE):
            return self._unescape_cpe(" ".join(self._cpe.get_vendor()))

    @property
    def cpe_product(self):
        """
        Get product name based on CPE

        Returns:
            str|None

        """
        if isinstance(self._cpe, CPE):
            return self._unescape_cpe(" ".join(self._cpe.get_product()))

    @property
    def cpe_version(self):
        """
        Get product name based on CPE

        Returns:
            str|None

        """
        if isinstance(self._cpe, CPE):
            return self._unescape_cpe(" ".join(self._cpe.get_version()))

    def __str__(self):
        return "{name} {version}".format(name=self.name or '', version=self.version or '').strip()

    def copy(self):
        """
        Make copy of service

        Returns:
            Service

        """
        return_value = Service(name=self.name, version=self.version)
        return_value._cpe = self._cpe
        return return_value

    @classmethod
    def _escape_cpe(cls, text):
        """
        Special characters should be escaped before building CPE string

        Args:
            text (str):

        Returns:
            str

        """
        text = text.lower()

        def _replace(txt):
            return r"\{0}".format(txt.group())

        if " " in text:
            raise ValueError("{0}: Space is not allowed in CPE string".format(text))

        return cls._ESCAPE_CPE.sub(_replace, text)

    @classmethod
    def _unescape_cpe(cls, text):
        text = text.lower()

        def _replace(txt):
            return txt.group()[1]

        return cls._UNESCAPE_CPE.sub(_replace, text)

    @classmethod
    def build_cpe(cls, type, vendor='*', product='*', version='*'):
        """
        Build cpe basing on vendor, product and version

        Args:
            type (CPEType:
            vendor (str):
            product (str):
            version (str):

        Returns:
            str

        """
        if vendor:
            vendor = cls._escape_cpe(vendor)

        if product:
            product = cls._escape_cpe(product)

        if version:
            version = cls._escape_cpe(version)

        return "cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*".format(part=str(type.value), vendor=vendor,
                                                                                  product=product, version=version)


class CPEType(Enum):
    """
    Type of CPE (application, hardware or os)

    """
    APPLICATION = "a"
    HARDWARE = "h"
    OS = "o"


class Port(object):
    """
    Port object

    """
    def __init__(self, node, number, transport_protocol):
        """
        Args:
            node (Node):
            number (int):
            transport_protocol (TransportProtocol):

        """
        self.vulnerabilities = []
        self.when_discovered = time.time()
        self.node = node
        self.number = number
        self.transport_protocol = transport_protocol
        self.service = Service()
        self.apps = []
        self.protocol = None
        self.banner = None
        self.scan = None
        self.interface = None

    def __eq__(self, other):
        return isinstance(other, Port) and self.transport_protocol == other.transport_protocol \
               and self.number == other.number and self.node == other.node

    def __ne__(self, other):
        return (not isinstance(other, Port)) or self.transport_protocol != other.transport_protocol \
               or self.number != other.number or self.node != other.node

    def __hash__(self):
        return hash((self.transport_protocol, self.number, self.node))

    def __str__(self):
        return '%s:%s' % (self.node.ip, self.number)

    def copy(self):
        """
        Return copy of port

        Returns:
            Port: copy of port

        """
        return_value = type(self)(node=self.node, number=self.number, transport_protocol=self.transport_protocol)
        return_value.vulnerabilities = self.vulnerabilities
        return_value.when_discovered = self.when_discovered
        return_value.service = self.service.copy()
        return_value.apps = [app.copy() for app in self.apps]
        return_value.banner = self.banner
        return_value.protocol = self.protocol
        return_value.scan = self.scan
        return_value.interface = self.interface
        return return_value

    @property
    def is_ipv6(self):
        """
        Returns True if node is using ipv6 addressing

        Returns:
            bool

        """
        return self.node.is_ipv6

    @property
    def url(self):
        """
        Returns node as URL string.

        Returns:
            str

        """
        if self.is_ipv6:
            format_string = "{0}://[{1}]:{2}"
        else:
            format_string = "{0}://{1}:{2}"
        return format_string.format(self.protocol, self.node.ip, self.number)

    def in_range(self, parsed_ports):
        """
        Check if port is in range of parsed_ports

        Args:
            parsed_ports (dict):

        Returns:
            bool

        """
        return self.number in parsed_ports[self.transport_protocol]


class SpecialPort(Port):
    """
    Class for special ports (broadcast, physical)

    """
    IP = ipaddress.ip_address("255.255.255.255")
    NODE_ID = 0xFFFFFFFF
    PROTOCOL = None

    def __init__(self, node=None, number=None, transport_protocol=None):
        super(SpecialPort, self).__init__(node=node or Node(node_id=self.NODE_ID, ip=self.IP), number=number or 0,
                                          transport_protocol=transport_protocol or self.PROTOCOL)


class BroadcastPort(SpecialPort):
    """
    Broadcast port

    """
    PROTOCOL = TransportProtocol.UDP

    def __str__(self):
        return 'broadcast'


class PhysicalPort(SpecialPort):
    """
    Physical port

    """
    PROTOCOL = TransportProtocol.PHY

    def __str__(self):
        return 'phy:{0}'.format(self.interface)


class Vulnerability(object):
    """
    Vulnerability object

    """
    def __init__(self, exploit=None, port=None, output=None):
        """
        Init values

        Args:
            exploit(Exploit): Exploit used to detect vulnerability
            port(Port): Vulnerable port
            output(str): string or stringable output

        """
        self.when_discovered = time.time()
        self.output = str(output)
        self.exploit = exploit
        self.port = port


class ScanStatus(Enum):
    """
    Scan status

    """
    IDLE = "IDLE"
    IN_PROGRESS = "IN PROGRESS"


class TopisOSDiscoveryType(Enum):
    """
    Type of Topdis OS discovery

    """
    FINGERPRINT = "OSFINGERPRINT"
    DIRECT = "DIRECT"
