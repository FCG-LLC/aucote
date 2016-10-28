"""
This module containstasks related to Aucote HTTP Headers
"""
import time
import requests

from structs import Vulnerability
from tools.common.port_task import PortTask


class AucoteHttpHeadersTask(PortTask):
    """
    This task check if required headers are used by HTTP server

    """

    MISSING_HEADER = 'Missing header: {name}:\n\t{description}'
    SUSPICIOUS_HEADER = "Suspicious header value: {name}: '{value}'\n\t{description}"

    def __init__(self, config, *args, **kwargs):
        self.config = config
        super(AucoteHttpHeadersTask, self).__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        custom_headers = {'Accept-Encoding:': 'gzip, deflate'}
        request = requests.head(self._port.url, headers=custom_headers)
        headers = request.headers

        results = []

        for header in self.config['headers']:
            if header.name in headers.keys():
                if not header.regex.match(headers[header.name]):
                    results.append(self.SUSPICIOUS_HEADER.format(name=header.name, value=headers[header.name],
                                                                 description=header.description))
            else:
                results.append(self.MISSING_HEADER.format(name=header.name, description=header.description))

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

        if not results:
            return results

        vulnerabilities = self.get_vulnerabilities("\n\n".join(results))

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                self.store_vulnerability(vulnerability)

        return results

    def get_vulnerabilities(self, results):
        """
        Gets vulnerabilities based upon results

        Args:
            results:

        Returns:
            list

        """
        return [Vulnerability(exploit=self.exploit, port=self._port, output=results)]
