from scans.scanner import Scanner
from structs import TransportProtocol
from tools.nmap.ports import PortsScan


class UDPScanner(Scanner):
    PROTOCOL = TransportProtocol.UDP

    @property
    def scanners(self):
        return {
            self.IPV4: [PortsScan(ipv6=False, tcp=False, udp=True)],
            self.IPV6: [PortsScan(ipv6=True, tcp=False, udp=True)]
        }
