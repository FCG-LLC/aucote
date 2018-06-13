"""
Database
========


Kudu database schema:

security_audits (0x8)
---------------

+-------------------+------------+------------+------+------+---------+------------+----------------------+---------+------------+-----------------+--------------+-----------------+----------------+-------------+--------------+------------------+--------+-----------+----------+--------------+------+-----+------+-----------------+
| time_stamp_bucket | server_ip1 | server_ip2 | port | prot | vuln_id | vuln_subid | time_stamp_remainder | node_id | scan_start | port_scan_start | service_name | service_version | service_banner | vuln_output | traffic_type | operating_system | metric | scan_name | app_name | exploit_name | tags | cve | cvss | expiration_time |
+===================+============+============+======+======+=========+============+======================+=========+============+=================+==============+=================+================+=============+==============+==================+========+===========+==========+==============+======+=====+======+=================+
+-------------------+------------+------------+------+------+---------+------------+----------------------+---------+------------+-----------------+--------------+-----------------+----------------+-------------+--------------+------------------+--------+-----------+----------+--------------+------+-----+------+-----------------+

columns:
 - time_stamp_bucket. time_stamp_remainder - calculated from port.scan.start
 - server_ip1, server_ip2 - calculated from Node IP
 - port - port based (number)
 - prot - port based (protocol (tcp, udp))
 - vuln_id - exploit base
 - vuln_subid - vulnerability subidentifier (allows to push multiple records for one vulnerability)
 - node_id - node based
 - scan_start - context.scan.scan_start
 - port_scan_start - port.scan.start
 - service_name - port based service (ftp, http, etc.)
 - service_version - port based (vuln_id=0, vuln_subid=3 for local storage)
 - service_banner - port based (vuln_id=0, vuln_subid=4 for local storage)
 - vuln_output - vulnerability based
 - traffic_type - internal
 - operating_system - port based (port.service.name and port.service.version)
 - metric - exploit based
 - scan_name - scan context based
 - app_name - exploit base
 - exploit_name - exploit base
 - tags - explot based
 - cve - vuln based
 - cvss - vuln based
 - expiration_time - vuln based


"""
from enum import Enum

from fixtures.exploits import Exploit
from structs import Vulnerability, VulnerabilityChange
from utils.kudu_queue import KuduMsg


class MsgType(Enum):
    """
    Class for message type
    """
    VULNERABILITY = 0x8
    EXPLOIT = 0x9
    CHANGE = 0xf


class Serializer:
    """
    Class for serializing objects
    """

    @classmethod
    def serialize_vulnerability(cls, vuln: Vulnerability) -> KuduMsg:
        """
        Serializes Vulnerability
        """
        msg = KuduMsg(MsgType.VULNERABILITY.value)
        msg.add_datetime(vuln.scan.start)  # scan_start
        msg.add_short(vuln.port.number)
        msg.add_ip(vuln.port.node.ip)
        msg.add_int(vuln.port.node.id)
        msg.add_str(vuln.port.protocol)
        msg.add_str(str(vuln.port.service))
        msg.add_str(vuln.port.banner)
        msg.add_byte(vuln.port.transport_protocol.iana)
        msg.add_datetime(vuln.port.scan.start)  # port_scan_start
        msg.add_str(vuln.output)
        msg.add_int(vuln.exploit.id if vuln.exploit is not None else 0)
        msg.add_int(vuln.subid)
        msg.add_datetime(vuln.time)
        msg.add_str(vuln.port.node.os.name_with_version)
        msg.add_str(vuln.exploit.metric.name if vuln.exploit is not None and vuln.exploit.metric is not None else '')
        msg.add_str(vuln.scan.scanner if vuln.scan is not None else '')
        msg.add_str(vuln.exploit.app if vuln.exploit is not None else '')
        msg.add_str(vuln.exploit.name if vuln.exploit is not None else '')
        msg.add_long(vuln.exploit.tags_mask if vuln.exploit is not None else 0)
        msg.add_str(vuln.cve)
        msg.add_byte(round(vuln.cvss*10))
        msg.add_datetime(vuln.expiration_time)
        return msg

    @classmethod
    def serialize_exploit(cls, exploit: Exploit) -> KuduMsg:
        """
        Serializes Exploit
        """
        msg = KuduMsg(MsgType.EXPLOIT.value)
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
        msg = KuduMsg(MsgType.CHANGE.value)
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
