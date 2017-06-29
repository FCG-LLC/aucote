from scans.scanner import Scanner
from tools.nmap.ports import PortsScan


class UDPScanner(Scanner):
    NAME = "udp"

    @property
    def scanners(self):
        return {
            self.IPV4: [PortsScan(ipv6=False, tcp=False, udp=True)],
            self.IPV6: [PortsScan(ipv6=True, tcp=False, udp=True)]
        }
