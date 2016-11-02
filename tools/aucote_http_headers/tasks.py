"""
This module contains tasks related to Aucote HTTP Headers

"""
import time
import requests

from structs import Vulnerability
from tools.aucote_http_headers.structs import AucoteHttpHeaderResult as Result
from tools.common.port_task import PortTask


class AucoteHttpHeadersTask(PortTask):
    """
    This task check if required headers are used by HTTP server

    Returns:
        list: list of AucoteHttpHeaderResult objects

    """
    MISSING_HEADER = 'Missing header: {name}'
    SUSPICIOUS_HEADER = "Suspicious header value: {name}: '{value}'"

    def __init__(self, config, *args, **kwargs):
        self.config = config
        super(AucoteHttpHeadersTask, self).__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        custom_headers = {'Accept-Encoding:': 'gzip, deflate'}
        request = requests.head(self._port.url, headers=custom_headers, verify=False)
        headers = request.headers

        results = []

        for exploit in self.current_exploits:
            header = self.config.get('headers', {}).get(exploit.name)
            if exploit.title in headers.keys():
                if not header.regex.match(headers[exploit.title]):
                    results.append(Result(output=self.SUSPICIOUS_HEADER.format(name=exploit.title,
                                                                               value=headers[exploit.title]),
                                          exploit=exploit))
            elif header.obligatory:
                results.append(Result(output=self.MISSING_HEADER.format(name=exploit.title),exploit=exploit))

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

        if not results:
            return results

        vulnerabilities = self.get_vulnerabilities(results)

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                self.store_vulnerability(vulnerability)

        return results

    def get_vulnerabilities(self, results):
        """
        Gets vulnerabilities based upon results

        Args:
            results(list): list of AucoteHttpHeaderResult

        Returns:
            list: list of Vulneravbilities

        """

        return_value = []

        for result in results:
            return_value.append(Vulnerability(exploit=result.exploit, port=self._port, output=result.output))
        return return_value
