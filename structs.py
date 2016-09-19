"""
This file provides structures for project.
"""

from enum import Enum
import time


class Scan(object):
    """
    Scan object
    """
    start = None
    end = None


class Node:
    """
    Node object consist of name, id and ip

    """

    def __init__(self, name=None, ip=None, id=None):
        """
        Init values
        Args:
            name (str):
            ip (IPv4Address):
            id (int):

        """
        self.name = name
        self.ip = ip
        self.id = id

    def __eq__(self, other):
        try:
            return self.ip == other.ip and self.id == other.id
        except AttributeError:
            return False

    def __ne__(self, other):
        try:
            return self.ip != other.ip or self.id != other.id
        except AttributeError:
            return True

    def __hash__(self):
        return hash("{id}:{ip}".format(id=self.id, ip=self.ip))


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
        raise ValueError('Invalid transport protocol name: %s'%name)

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
        raise ValueError('Unsupported risk level name: %s'%name)


class Port(object):
    """
    Port object

    """
    TABLE = 'ports'

    def __init__(self, node=None, number=None, transport_protocol=None, service_name=None, service_version=None,
                 banner=None):
        """

        Args:
            node (Node):
            number (int):
            transport_protocol (TransportProtocol):
            service_name (str):
            service_version (str):
            banner (str):

        """
        self.vulnerabilities = []
        self.when_discovered = time.time()
        self.node = node
        self.number = number
        self.transport_protocol = transport_protocol
        self.service_name = service_name
        self.service_version = service_version
        self.banner = banner
        self.scan = None

    def __eq__(self, other):
        try:
            return self.transport_protocol == other.transport_protocol and self.number == other.number \
                   and self.node == other.node
        except AttributeError:
            return False

    def __ne__(self, other):
        try:
            return self.transport_protocol != other.transport_protocol or self.number != other.number \
                   or self.node != other.node
        except AttributeError:
            return True

    def __hash__(self):
        return hash("{protocol}:{number}:{node}".format(protocol=self.transport_protocol, number=self.number,
                                                        node=hash(self.node)))

    def __str__(self):
        return '%s:%s' % (self.node.ip, self.number)


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
