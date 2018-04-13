"""
Provides serializers for database
"""
from enum import Enum

from math import floor

from fixtures.exploits import Exploit
from structs import Vulnerability, Port, VulnerabilityChange
from utils.kudu_queue import KuduMsg


class MsgType(Enum):
    """
    Class for message type
    """
    VULNERABILITY = 0
    EXPLOIT = 1
    CHANGE = 2


class Serializer:
    """
    Class for serializing objects
    """

    @classmethod
    def serialize_vulnerability(cls, vuln: Vulnerability) -> KuduMsg:
        """
        Serializes Vulnerability
        """
        msg = KuduMsg()
        msg.add_short(MsgType.VULNERABILITY.value)
        msg.add_datetime(vuln.port.scan.start)  # scan_start
        msg.add_short(vuln.port.number)
        msg.add_ip(vuln.port.node.ip)
        msg.add_int(vuln.port.node.id)
        msg.add_str(vuln.port.protocol)
        msg.add_str(str(vuln.port.service))
        msg.add_str(vuln.port.banner)
        msg.add_byte(vuln.port.transport_protocol.iana)
        msg.add_datetime(vuln.port.when_discovered)  # port_scan_start
        msg.add_str(vuln.output)
        msg.add_int(vuln.exploit.id if vuln.exploit is not None else 0)
        msg.add_int(vuln.subid)
        msg.add_datetime(vuln.when_discovered)
        msg.add_str(vuln.port.node.os.name_with_version)
        msg.add_str(vuln.exploit.metric.name if vuln.exploit is not None and vuln.exploit.metric is not None else '')
        msg.add_str(vuln.context.scan.NAME if vuln.context is not None else '')
        msg.add_str(vuln.exploit.app if vuln.exploit is not None else '')
        msg.add_str(vuln.exploit.name if vuln.exploit is not None else '')
        msg.add_long(vuln.exploit.tags_mask if vuln.exploit is not None else 0)
        msg.add_str(vuln.cve)
        msg.add_byte(floor(vuln.cvss*10))
        return msg

    @classmethod
    def serialize_exploit(cls, exploit: Exploit) -> KuduMsg:
        """
        Serializes Exploit
        """
        msg = KuduMsg()
        msg.add_short(MsgType.EXPLOIT.value)
        msg.add_int(exploit.id)
        msg.add_str(exploit.app)
        msg.add_str(exploit.name)
        msg.add_str(exploit.title)
        msg.add_str(exploit.description)
        msg.add_byte(exploit.risk_level.number)
        msg.add_str(exploit.category.value)
        msg.add_long(exploit.tags_mask)
        return msg

    @classmethod
    def serialize_vulnerability_change(cls, vuln_change: VulnerabilityChange) -> KuduMsg:
        """
        Serializes VulnerabilityChange
        """
        msg = KuduMsg()
        msg.add_short(MsgType.CHANGE.value)
        msg.add_ip(vuln_change.node_ip)
        msg.add_short(vuln_change.port_number)
        msg.add_byte(vuln_change.port_protocol.iana)
        msg.add_int(vuln_change.vulnerability_id)
        msg.add_int(vuln_change.vulnerability_subid)
        msg.add_datetime(vuln_change.time)
        msg.add_int(vuln_change.node_id)
        msg.add_byte(vuln_change.score)
        msg.add_datetime(vuln_change.previous_scan)
        msg.add_datetime(vuln_change.current_scan)
        msg.add_str(vuln_change.previous_output)
        msg.add_str(vuln_change.current_output)
        msg.add_str(vuln_change.description)
        return msg
