from tornado.ioloop import IOLoop

from scans.scanner import Scanner
from structs import TransportProtocol
from utils.portscan import PortscanScanner


class TCPScanner(Scanner):
    PROTOCOL = TransportProtocol.TCP
    NAME = 'tcp'

    def __init__(self, host, port, *args, **kwargs):
        super(TCPScanner, self).__init__(*args, **kwargs)
        self.host = host
        self.port = port
        self._tcp_scanner = PortscanScanner(self.host, self.port, IOLoop.current().instance())

    @property
    def scanners(self):
        return {
            self.IPV4: [self._tcp_scanner],
            self.IPV6: [self._tcp_scanner]
        }
