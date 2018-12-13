"""
This file provides structures for project.

"""
import ipaddress
import re
from abc import ABCMeta, abstractmethod
from ctypes import c_uint32
from enum import Enum
import time
import logging as log

from cpe import CPE
from tornado import gen

from fixtures.exploits import Exploit


class Scan(object):
    """
    Scan object. Contains rowid for identification in storage.

    """

    def __init__(self, start=None, end=None, protocol=None, scanner='', rowid=None, init=True):
        """
        Args:
            protocol TransportProtocol: scan protocol
            start (int|float): start scan time
            end (int|float): end scan time
            scanner (str): scanner name

        """
        self._start_ms = None
        self._end_ms = None

        self.rowid = rowid
        self.start = time.time() if start is None and init is True else start
        self.end = end
        self._protocol = protocol
        self._scanner = scanner

    @property
    def start(self) -> float:
        """
        Scan start (unix timestamp) in seconds
        """
        return self._start_ms / 1000 if self._start_ms is not None else None

    @start.setter
    def start(self, value: float):
        self._start_ms = round(value * 1000) if value is not None else None

    @property
    def end(self) -> float:
        """
        Scan end (unix timestamp) in seconds
        """
        return self._end_ms / 1000 if self._end_ms is not None else None

    @end.setter
    def end(self, value: float):
        self._end_ms = round(value * 1000) if value is not None else None

    @property
    def protocol(self):
        """
        Scan protocol

        Returns:
            TransportProtocol

        """
        return self._protocol

    @property
    def scanner(self):
        """
        Name of used scanner

        Returns:
            Scan

        """
        return self._scanner

    def __eq__(self, other):
        """

        Args:
            other (Scan):

        Returns:
            bool

        """
        return isinstance(other, Scan) and all((self.scanner == other.scanner, self.start == other.start,
                                                self.protocol == other.protocol))

    def __hash__(self):
        return hash((self.scanner, self.start, self.protocol))


class Node:
    """
    Represents node in the network. Every pair ip:node_id is considered as separated node
    """
    DEFAULT_VALUE = 0

    def __init__(self, node_id, ip):
        """
        Init values
        Args:
            node_id (int):
            ip (IPv4Address):

        """
        self.name = None
        self.ip = ip
        self._id = self.DEFAULT_VALUE
        self.id = node_id
        self.scan = None
        self.os = Service()

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        """
        Set node id. If it's negative, convert to unsigned int
        """
        if value is None:
            value = self.DEFAULT_VALUE

        self._id = c_uint32(value).value

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


class NodeScan(object):
    """
    Represents node scan. Contains rowid for identification in storage.

    """

    def __init__(self, node, scan, timestamp, rowid=None):
        self.node = node
        self.scan = scan
        self.timestamp = timestamp
        self.rowid = rowid

    def __eq__(self, other):
        return isinstance(other, NodeScan) and all((self.node == other.node, self.scan == other.scan))


class PortScan(object):
    """
    Represents node scan. Contains rowid for identification in storage.

    """

    def __init__(self, port, scan, timestamp=None, rowid=None):
        self.port = port
        self.scan = scan
        self.timestamp = timestamp
        self.rowid = rowid

    def __eq__(self, other):
        return isinstance(other, PortScan) and all((self.port == other.port, self.scan == other.scan))

    @property
    def node(self):
        """
        Node on which PortScan is performed

        Returns:
            Node

        """
        return self.port.node

    def __hash__(self):
        return hash((self.port, self.scan))


class SecurityScan(object):
    """
    SecurityScan is a single scan performed by given exploit on given port during specific global scan (e.g. TCP scan)

    """
    def __init__(self, scan, port, exploit, scan_start=None, scan_end=None, rowid=None):
        self._scan_start_ms = None

        self.port = port
        self.exploit = exploit
        self.scan_start = scan_start
        self.scan = scan
        self.scan_end = scan_end
        self.rowid = rowid

    @property
    def node(self):
        """
        Node for which security scan wis performed

        Returns:
            Node

        """
        return self.port.node
    
    @property
    def scan_start(self):
        """
        Scan start in seconds
        """
        return self._scan_start_ms / 1000 if self._scan_start_ms is not None else None

    @scan_start.setter
    def scan_start(self, value):
        self._scan_start_ms = round(value * 1000) if value is not None else None

    def __eq__(self, other):
        return isinstance(other, SecurityScan) and all((self.port == other.port, self.exploit == other.exploit,
                                                        self.scan == other.scan))

    def __hash__(self):
        return hash((self.port, self.exploit, self.scan))


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


class Service(object):
    """
    Represents service/application/operating system. Contains basic information: name, version

    """
    _CPE_SPECIAL = r"\!|\"|\;|\#|\$|\%|\&|\'|\(|\)|\+|\,|\/|\:|\<|\=|\>|\@|\[|\]|\^|\`|\{|\||\}|\~|\-"
    _ESCAPE_CPE = re.compile(_CPE_SPECIAL)
    _UNESCAPE_CPE = re.compile(r"(\\({0}))".format(_CPE_SPECIAL))

    def __init__(self, name=None, version=None, cpe=None):
        self.name = name
        self.version = version
        self._cpe = None
        self.cpe = cpe

    @property
    def cpe(self) -> CPE:
        """
        CPE representation of service
        """
        return self._cpe

    @cpe.setter
    def cpe(self, value):
        if value:
            self._cpe = CPE(value)

    @property
    def cpe_vendor(self) -> str:
        """
        Get vendor name based on CPE
        """
        if isinstance(self._cpe, CPE):
            return self._unescape_cpe(" ".join(self._cpe.get_vendor()))

    @property
    def name_with_version(self) -> str:
        """
        Service name with version included
        """
        if self.version is None or self.name is None:
            return None
        return "{name} {version}".format(name=self.name, version=self.version)

    @property
    def cpe_product(self) -> str:
        """
        Get product name based on CPE
        """
        if isinstance(self._cpe, CPE):
            return self._unescape_cpe(" ".join(self._cpe.get_product()))

    @property
    def cpe_version(self) -> str:
        """
        Get product name based on CPE
        """
        if isinstance(self._cpe, CPE):
            return self._unescape_cpe(" ".join(self._cpe.get_version()))

    def __str__(self):
        return "{name} {version}".format(name=self.name or '', version=self.version or '').strip()

    def copy(self) -> 'Service':
        """
        Make copy of service
        """
        return_value = Service(name=self.name, version=self.version)
        return_value._cpe = self._cpe
        return return_value

    @classmethod
    def _escape_cpe(cls, text: str) -> str:
        """
        Special characters should be escaped before building CPE string
        """
        text = text.lower()

        def _replace(txt):
            return r"\{0}".format(txt.group())

        if " " in text:
            raise ValueError("{0}: Space is not allowed in CPE string".format(text))

        return cls._ESCAPE_CPE.sub(_replace, text)

    @classmethod
    def _unescape_cpe(cls, text: str) -> str:
        text = text.lower()

        def _replace(txt):
            return txt.group()[1]

        return cls._UNESCAPE_CPE.sub(_replace, text)

    @classmethod
    def validate_cpe_arguments(cls, vendor: str, product: str, version: str) -> (str, str, str):
        """
        Validate cpe arguments, and fix as much as possible
        """
        if " " in version:
            if product.lower() == "ios":
                version = version.split(" ")[0].strip(",")

        if vendor == "*":
            if product.lower() == "ios":
                vendor = "cisco"

        return cls._escape_cpe(vendor), cls._escape_cpe(product), cls._escape_cpe(version)

    @classmethod
    def build_cpe(cls, part: 'CPEType', vendor: str = '*', product: str = '*', version: str = '*') -> str:
        """
        Build cpe 2.3 string base on vendor, product, version and part
        """
        vendor, product, version = cls.validate_cpe_arguments(vendor=vendor, product=product, version=version)

        return "cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*".format(part=str(part.value), vendor=vendor,
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
    PROTOCOLS_MAP = {
        'http-proxy': 'http'
    }

    def __init__(self, node, number, transport_protocol, scan=None):
        """
        Args:
            node (Node):
            number (int):
            transport_protocol (TransportProtocol):

        """
        self.vulnerabilities = []
        self.node = node
        self.number = number
        self.transport_protocol = transport_protocol
        self.service = Service()
        self.apps = []
        self.protocol = None
        self.banner = None
        self.scan = scan
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

        return format_string.format(self.PROTOCOLS_MAP.get(self.protocol, self.protocol), self.node.ip, self.number)

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
        return '{0}:phy:{1}'.format(self.node.ip, self.interface)


class Vulnerability(object):
    """
    Vulnerability object. Contains rowid for identification in storage.

    """
    PORTDETECTION = 0
    SERVICE_PROTOCOL = 1
    SERVICE_NAME = 2
    SERVICE_VERSION = 3
    SERVICE_BANNER = 4
    SERVICE_CPE = 5
    OS_NAME = 6
    OS_VERSION = 7
    OS_CPE = 8

    def __init__(self, exploit=None, port=None, output='', cve=None, cvss=None, subid=0, vuln_time=None,
                 rowid=None, scan=None, context=None, expiration_time=None):
        """
        Init values

        Args:
            exploit(Exploit): Exploit used to detect vulnerability
            port(Port): Vulnerable port
            output(str): string or stringable output

        """
        self._time_ms = None
        self._expiration_time_ms = None

        self.output = str(output) if output is not None else None
        self.exploit = exploit if exploit is not None else Exploit(exploit_id=0)
        self.port = port
        self._cve = cve
        self._cvss = cvss
        self.subid = subid
        self.time = vuln_time or time.time()
        self.rowid = rowid
        self.scan = scan
        self.context = context
        self.expiration_time = expiration_time

    @property
    def time(self):
        return self._time_ms / 1000 if self._time_ms is not None else None

    @time.setter
    def time(self, value):
        """
        Detection time in seconds (unix timestamp)
        """
        self._time_ms = round(value * 1000) if value is not None else None

    @property
    def expiration_time(self):
        """
        Vulnerability expiration time in seconds (unix timestamp)
        """
        return self._expiration_time_ms / 1000 if self._expiration_time_ms is not None else None

    @expiration_time.setter
    def expiration_time(self, value):
        self._expiration_time_ms = round(value * 1000) if value is not None else None

    @property
    def cve(self):
        return self._cve if self._cve is not None else self.exploit.cve if self.exploit else ''

    @property
    def cvss(self):
        return float(self._cvss) if self._cvss is not None else self.exploit.cvss if self.exploit is not None else 0.

    def __eq__(self, other):
        return isinstance(other, Vulnerability) and self.port == other.port and self.exploit == other.exploit and \
               self.subid == other.subid and self.output == other.output and self.cve == other.cve and \
               self.cvss == other.cvss

    def is_almost_equal(self, other):
        """
        Check if vulnerability is this same but with different output

        Args:
            other (Vulnerability):

        Returns:
            bool

        """
        return isinstance(other, Vulnerability) and self.port == other.port and self.exploit == other.exploit and \
               self.subid == other.subid

    def __hash__(self):
        return hash((self.port, self.exploit, self.subid, self.output, self.cve, self.cvss))


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


class ScanType(Enum):
    """
    Scan types

    """
    PERIODIC = "PERIODIC"
    LIVE = "LIVE"


class PortState(Enum):
    """
    Port state

    """
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"

    @classmethod
    def from_string(cls, text):
        """
        Return PortState based on string

        Args:
            text (str):

        Returns:
            PortState

        """
        return cls[text.replace('|', '_').upper()]


class VulnerabilityChangeType(Enum):
    """
    Vulnerability change type

    """
    PORTDETECTION = 1
    VULNERABILITIES = 2


class VulnerabilityChangeBase(metaclass=ABCMeta):
    """
    Represents change between two port or severity scans

    """

    def __init__(self, change_type, vulnerability_id, vulnerability_subid, current_finding, previous_finding,
                 change_time=None, score=0):
        """

        Args:
            change_type (VulnerabilityChangeType):
            vulnerability_id (int):
            vulnerability_subid (int):
            current_finding (object):
            previous_finding (object):
            change_time (int):

        """
        self.type = change_type
        self.vulnerability_id = vulnerability_id
        self.vulnerability_subid = vulnerability_subid
        self.current_finding = current_finding
        self.previous_finding = previous_finding
        self.time = change_time or time.time()
        self.score = score

    def __eq__(self, other):
        return isinstance(other, VulnerabilityChangeBase) and self.vulnerability_subid == other.vulnerability_subid \
               and self.vulnerability_id == other.vulnerability_id and self.previous_finding == other.previous_finding \
               and self.type == other.type and self.current_finding == other.current_finding

    def __hash__(self):
        return hash((self.type, self.vulnerability_id, self.vulnerability_subid, self.current_finding,
                     self.previous_finding))

    @property
    def finding(self):
        """
        Returns one of the finding. As findings should be the same class objects, and handle information about this same
        port, there is enough to return any of them

        Returns:
            object

        """
        return self.current_finding or self.previous_finding

    @property
    @abstractmethod
    def port(self):
        """

        Returns:
            Port
        """
        pass

    @property
    def node_ip(self):
        """
        Ip of node which change

        Returns:
            IPv4Address|IPv6Address

        """
        return self.port.node.ip

    @property
    def node_id(self):
        """
        Id of node which change

        Returns:
            int

        """
        return self.port.node.id

    @property
    @abstractmethod
    def previous_scan(self):
        """
        Previous scan timestamp

        Returns:
            int

        """
        pass

    @property
    @abstractmethod
    def current_scan(self):
        """
        Current scan timestamp

        Returns:
            int

        """
        pass

    @property
    def port_number(self):
        """
        Number of port which change

        Returns:
            int

        """
        return self.port.number

    @property
    def port_protocol(self):
        """
        Protocol of port which change

        Returns:
            TransportProtocol

        """
        return self.port.transport_protocol

    @property
    @abstractmethod
    def description(self):
        """
        Human friendly description of change

        Returns:
            str

        """
        pass

    @property
    @abstractmethod
    def previous_output(self):
        """
        Output of previous finding

        Returns:
            str

        """
        pass

    @property
    @abstractmethod
    def current_output(self):
        """
        Output of current finding

        Returns:
            str

        """
        pass


class PortDetectionChange(VulnerabilityChangeBase):
    """
    Represents change between two port detection scans

    """

    def __init__(self, *args, **kwargs):
        """

        Args:
            current_finding (Port):
            previous_finding (Port):

        """
        super(PortDetectionChange, self).__init__(change_type=VulnerabilityChangeType.PORTDETECTION,
                                                  vulnerability_id=0,
                                                  vulnerability_subid=Vulnerability.PORTDETECTION, *args, **kwargs)

    @property
    def description(self):
        if self.previous_finding and not self.current_finding:
            return "Port disappeared"
        elif self.current_finding and not self.previous_finding:
            return "New port discovered"

    @property
    def port(self):
        return self.finding.port

    @property
    def previous_scan(self):
        return self.previous_finding and self.previous_finding.scan.start

    @property
    def current_scan(self):
        return self.current_finding and self.current_finding.scan.start

    @property
    def previous_output(self):
        return ""

    @property
    def current_output(self):
        return ""


class VulnerabilityChange(VulnerabilityChangeBase):
    """
    Represents change between two vulnerability scans for specific node and port

    """

    def __init__(self, *args, **kwargs):
        super(VulnerabilityChange, self).__init__(change_type=VulnerabilityChangeType.VULNERABILITIES,
                                                  vulnerability_id=None, vulnerability_subid=None, *args, **kwargs)
        self.vulnerability_id = self.finding.exploit.id
        self.vulnerability_subid = self.finding.subid

    @property
    def port(self):
        return self.finding.port

    @property
    def previous_scan(self):
        return self.previous_finding and self.previous_finding.time

    @property
    def current_scan(self):
        return self.current_finding and self.current_finding.time

    @property
    def description(self):
        if self.previous_finding and not self.current_finding:
            return "Vulnerability disappeared"
        elif self.current_finding and not self.previous_finding:
            return "Vulnerability appeared"
        elif self.current_finding and self.previous_finding:
            return "Vulnerability changed"

    @property
    def previous_output(self):
        return self.previous_finding.output if self.previous_finding else ""

    @property
    def current_output(self):
        return self.current_finding.output if self.current_finding else ""


class ScanContext:
    """
    Scan context handle information about scan and it progress
    """
    def __init__(self, aucote, scanner):
        self.aucote = aucote
        self.scanner = scanner
        self.tasks = []
        self._cancelled = False
        self.start = None
        self._end = None

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, val):
        self._end = val
        self._post_scan_hook()

    @property
    def scan(self):
        return self.scanner.scan

    def _post_scan_hook(self):
        """
        Executes post scan operations

        """
        log.debug('Executing post scan hook for scan %s', self.scanner.NAME)

    def add_task(self, task, task_manager: str = None):
        if task_manager is None:
            task_manager = self.aucote.TASK_MANAGER_REGULAR

        self.tasks.append(task)
        if self._cancelled:
            task.cancel()
            return

        self.aucote.add_async_task(task, task_manager=task_manager)

    def is_scan_end(self):
        if self.end is None or self.unfinished_tasks():
            return False

        return True

    async def wait_on_tasks_finish(self):
        while self.unfinished_tasks():
            await gen.sleep(1)

    async def wait_on_scan_end(self):
        while not self.is_scan_end():
            await gen.sleep(1)

    def unfinished_tasks(self):
        return [task for task in self.tasks if not task.has_finished()]

    def cancel(self):
        self._cancelled = True

    def cancelled(self):
        return self._cancelled
