"""
This file provides structures for project.

"""
import ipaddress
from enum import Enum
import time


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
        self.start = start
        self.end = end


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

    def __eq__(self, other):
        return isinstance(other, Node) and self.ip == other.ip and self.id == other.id

    def __ne__(self, other):
        return (not isinstance(other, Node)) or self.ip != other.ip or self.id != other.id

    def __hash__(self):
        return hash((self.id, self.ip))

    @property
    def is_ipv6(self):
        return isinstance(self.ip, ipaddress.IPv6Address)


class TransportProtocol(Enum):
    """
    Transport protocol object consist of db_val and IANA val

    """

    def __init__(self, db_val, iana):
        self.db_val = db_val
        self.iana = iana

    TCP = ('TCP', 6)
    UDP = ('UDP', 17)
    ICMP = ('ICMP', 1)
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


class Port(object):
    """
    Port object

    """
    TABLE = 'ports'

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
        self.service_name = None
        self.service_version = None
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

    @classmethod
    def broadcast(cls):
        """
        Get broadcast Port

        Returns:
            Port

        """
        return cls(node=Node(node_id=0xFFFFFFFF, ip=ipaddress.ip_address('255.255.255.255')), number=0,
                   transport_protocol=TransportProtocol.UDP)

    @classmethod
    def physical(cls):
        """
        Get physical port structure

        Returns:
            Port

        """
        return cls(node=Node(node_id=0xFFFFFFFF, ip=ipaddress.ip_address('255.255.255.255')), number=0,
                   transport_protocol=TransportProtocol.PHY)

    @property
    def is_ipv6(self):
        return self.node.is_ipv6


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
