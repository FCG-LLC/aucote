from asyncio import get_event_loop

from scans.scanner import Scanner
from structs import TransportProtocol
from tools.nmap.ports import PortsScan


class TCPScanner(Scanner):
    PROTOCOL = TransportProtocol.TCP
    NAME = 'tcp'

    def __init__(self, host, port, *args, **kwargs):
        super(TCPScanner, self).__init__(*args, **kwargs)
        self.host = host
        self.port = port

    @property
    def scanners(self):
        return {
            self.IPV4: [PortsScan(ipv6=False, tcp=True, udp=False)],
            self.IPV6: [PortsScan(ipv6=True, tcp=True, udp=False)]
        }
