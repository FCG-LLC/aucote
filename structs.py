"""
This file provides structures for project.
"""

from enum import Enum
import datetime

from utils.database import DbObject


class Scan(DbObject):
    """
    Scan object
    """
    start = None
    end = None


class Node:
    """
    Node object consist of name, id and ip
    """
    name = None
    ip = None
    id = None


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
            name: string representation of transport protocol, eg. "tcp", "udp"

        Returns: TransportProtocol object

        Raises: ValueError if not: tcp, udp or icmp
        """
        name = name.upper()
        for val in cls:
            if val.db_val == name:
                return val
        raise ValueError('Invalid transport protocol name: %s'%name)


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

        Returns: RiskLevel object

        Raises: ValueError if not: High, Medium, Low or None
        """
        for val in cls:
            if val.txt == name:
                return val
        raise ValueError('Unsupported risk level name: %s'%name)


class Port(DbObject):
    """
    Port object
    """
    TABLE = 'ports'
    def __init__(self):
        self.vulnerabilities = []
        self.when_discovered = datetime.datetime.utcnow()

    node = None
    number = None
    transport_protocol = None
    service_name = None
    service_version = None
    banner = None
    when_discovered = None

    def __str__(self):
        return '%s:%s'%(self.node.ip, self.number)


class Vulnerability(DbObject):
    """
    Vulnerability object
    """
    def __init__(self):
        self.when_discovered = datetime.datetime.utcnow()
    exploit = None
    port = None
    output = None
    when_discovered = None
