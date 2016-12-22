"""
Provides serializers for database
"""
import codecs
import struct
from enum import Enum
from utils.kudu_queue import KuduMsg


class MsgType(Enum):
    """
    Class for message type
    """
    VULNERABILITY = 0
    EXPLOIT = 1


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
        msg.add_str(port.service_name or '')
        msg.add_str(port.service_version or '')
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
    def deserialize_port_vuln(cls, bytes):
        """
        Deserialize kudu message and return dict with deserialization result
        Args:
            bytes (str): hexstring, eg. 000FABC000...

        Returns:
            dict: - dict with keys:
                - server_ip1 (int): always 0
                - server_ip2 (int): ipv4 address
                - port (int)
                - prot (int)
                - vuln_id (int)
                - node_id (int)
                - scan_start (int)
                - port_scan_start (int)
                - service_name (str)
                - service_version (str)
                - service_banner (str)
                - vuln_output (str)
                - timestamp_bucket (int)
                - key - hash of (timestamp_bucket, server_ip1, server_ip2, port_number, protocol, exploit_id,
                                 timestamp_remainder)

        """
        hex = codecs.decode(bytes, "hex")
        (msg_type, port_scan_start, port_number, node_ip, node_id, service_name_length) = \
            struct.unpack('<hqh16sih', hex[:34])

        counter = 34

        (service_name, service_version_length) = \
            struct.unpack('<{service_name_length}sh'.format(counter=counter,
                                                                           service_name_length=service_name_length),
                               hex[counter:counter+service_name_length+2])

        counter += service_name_length + 2

        (service_version, banner_length) = \
            struct.unpack('<{service_version_length}sh'.format(service_version_length=service_version_length),
                               hex[counter:counter+service_version_length + 2])

        counter += service_version_length + 2

        (banner, protocol, port_when_discovered, vuln_output_length) = \
            struct.unpack('<{banner_length}sbqh'.format(banner_length=banner_length),
                          hex[counter:counter+banner_length + 11])

        counter += banner_length + 11

        (vuln_output, exploit_id, vuln_when_discovered) = \
            struct.unpack('<{vuln_output_length}siq'.format(vuln_output_length=vuln_output_length), hex[counter:])

        server_ip2 = int(codecs.encode(node_ip[2:6], "hex"), 16)
        timestamp = vuln_when_discovered or port_scan_start
        timestamp_bucket = int(timestamp/60000)*60
        timestamp_remainder = (timestamp - timestamp_bucket*1000)*1000
        key = hash((timestamp_bucket, 0, server_ip2, port_number, protocol, exploit_id, timestamp_remainder))

        return {
            'server_ip1': None,
            'server_ip2': server_ip2,
            'port': port_number,
            'prot':protocol,
            'vuln_id': exploit_id,
            'node_id': node_id,
            'scan_start': port_scan_start,
            'port_scan_start': port_when_discovered,
            'service_name': service_name.decode(),
            'service_version': service_version.decode(),
            'service_banner': banner.decode(),
            'vuln_output': vuln_output.decode(),
            'vuln_when_discovered': vuln_when_discovered,
            'timestamp_bucket': timestamp_bucket,
            'key': key,
        }