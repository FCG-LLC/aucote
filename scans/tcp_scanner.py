from scans.scanner import Scanner
from structs import TransportProtocol
from tools.masscan import MasscanPorts
from tools.nmap.ports import PortsScan


class TCPScanner(Scanner):
    PROTOCOL = TransportProtocol.TCP

    @property
    def scanners(self):
        return {
            self.IPV4: [MasscanPorts(udp=False)],
            self.IPV6: [PortsScan(ipv6=True, tcp=True, udp=False)]
        }
