"""
Provides serializers for database
"""
from enum import Enum
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
    def serialize_port_vuln(cls, port, vuln):
        """
        Function which return serialized port and vuln objects
        Args:
            port: Port object
            vuln: Vulnerability object

        Returns: Serialized objects as string

        """
        msg = KuduMsg()
        msg.add_short(MsgType.VULNERABILITY.value)
        msg.add_datetime(port.scan.start)  # scan_start
        msg.add_short(port.number)
        msg.add_ip(port.node.ip)
        msg.add_int(port.node.id)
        msg.add_str(port.protocol or '')
        msg.add_str(str(port.service) or '')
        msg.add_str(port.banner or "")
        msg.add_byte(port.transport_protocol.iana)
        msg.add_datetime(port.when_discovered)  # port_scan_start
        msg.add_str(vuln.output if vuln is not None else '')
        msg.add_int(vuln.exploit.id if vuln is not None else 0)
        msg.add_datetime(vuln.when_discovered if vuln is not None else None)
        return msg

    @classmethod
    def serialize_exploit(cls, exploit):
        """
        Function which return serialized exploit object
        Args:
            exploit: Exploit object

        Returns: Serialized object as string

        """
        msg = KuduMsg()
        msg.add_short(MsgType.EXPLOIT.value)
        msg.add_int(exploit.id)
        msg.add_str(exploit.app)
        msg.add_str(exploit.name)
        msg.add_str(exploit.title)
        msg.add_str(exploit.description)
        msg.add_byte(exploit.risk_level.number)
        return msg

    @classmethod
    def serialize_vulnerability_change(cls, vuln_change):
        """

        Args:
            vuln_change (VulnerabilityChangeBase):

        Returns:

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
