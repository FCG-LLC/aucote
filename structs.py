from utils.database import DbObject
from enum import Enum
import datetime


class Scan(DbObject):
    start = None
    end = None


class Node:
    name = None
    ip = None
    id = None


class TransportProtocol(Enum):
    def __init__(self, db_val, iana):
        self.db_val = db_val
        self.iana = iana

    TCP = ('TCP', 6)
    UDP = ('UDP', 17)
    ICMP = ('ICMP', 1)

    @classmethod
    def from_nmap_name(cls, name):
        name = name.upper()
        for val in cls:
            if val.db_val == name:
                return val
        raise ValueError('Invalid transport protocol name: %s'%name)


class RiskLevel(Enum):
    def __init__(self, txt, number):
        self.txt = txt
        self.number = number

    HIGH = ('High', 3)
    MEDIUM = ('Medium', 2)
    LOW = ('Low', 1)
    NONE = ('None', 0)

    @classmethod
    def from_name(cls, name):
        for val in cls:
            if val.txt == name:
                return val
        raise ValueError('Unsupported risk level name: %s'%name)


class Port(DbObject):
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
    def __init__(self):
        self.when_discovered = datetime.datetime.utcnow()
    exploit = None
    port = None
    output = None
    when_discovered = None
