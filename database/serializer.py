from utils.kudu_queue import KuduMsg
from enum import Enum

class MsgType(Enum):
    VULNERABILITY = 0
    EXPLOIT  = 1

class Serializer:
    def serialize_port_vuln(self, port, vuln):
        msg = KuduMsg()
        msg.add_short(MsgType.VULNERABILITY)
        msg.add_datetime(port.scan.start)
        msg.add_short(port.number)
        msg.add_ip(port.node.ip)
        msg.add_int(port.node.id)
        msg.add_str(port.service_name or '')
        msg.add_str(port.service_version or '')
        msg.add_str(port.banner or "")
        msg.add_byte(port.transport_protocol.iana)
        msg.add_datetime(port.when_discovered)
        msg.add_str(vuln.output if vuln is not None else '')
        msg.add_int(vuln.exploit.id if vuln is not None else 0)
        msg.add_datetime(vuln.when_discovered if vuln is not None else None)
        return msg

    def serialize_exploit(self, exploit):
        msg = KuduMsg()
        msg.add_short(MsgType.EXPLOIT)
        msg.add_int(exploit.id)
        msg.add_str(explot.app)
        msg.add_str(exploit.name)
        msg.add_str(exploit.title)
        msg.add_str(exploit.description)
        msg.add_byte(exploit.risk_level.number)
        return msg
        
