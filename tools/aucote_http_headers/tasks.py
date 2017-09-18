"""
This module contains tasks related to Aucote HTTP Headers

"""
import time
import logging as log

from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from structs import Vulnerability
from tools.aucote_http_headers.structs import AucoteHttpHeaderResult as Result
from tools.common.port_task import PortTask
from utils.http_client import HTTPClient


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

    async def __call__(self, *args, **kwargs):
        custom_headers = {
            'Accept-Encoding': 'gzip, deflate'
        }

        useragent = cfg['tools.common.http.useragent']
        if useragent is not None:
            custom_headers['User-Agent'] = useragent

        try:
            response = await HTTPClient.instance().head(url=self._port.url, headers=custom_headers, validate_cert=False)
        except HTTPError as exception:
            if exception.response is None:
                return
            response = exception.response
        except ConnectionError:
            log.exception("Cannot connect to %s", self._port.url)
            return
        except OSError as exception:
            log.warning("%s for %s", str(exception), self._port.url)
            return

        if response.code != 200:
            log.warning("Server replied with status code: %i", response.code)
        headers = response.headers

        results = []

        for exploit in self.current_exploits:
            header = self.config.get('headers', {}).get(exploit.name)
            if exploit.title in headers.keys():
                if not header.regex.match(headers[exploit.title]):
                    results.append(Result(output=self.SUSPICIOUS_HEADER.format(name=exploit.title,
                                                                               value=headers[exploit.title]),
                                          exploit=exploit))
            elif header.obligatory:
                results.append(Result(output=self.MISSING_HEADER.format(name=exploit.title), exploit=exploit))

        self._port.scan.end = int(time.time())
        self.store_scan_end(exploits=self.current_exploits, port=self._port)

        if not results:
            return results

        vulnerabilities = self._get_vulnerabilities(results)
        self.store_vulnerabilities(vulnerabilities)

        return results

    def _get_vulnerabilities(self, results):
        return_value = []

        for result in results:
            return_value.append(Vulnerability(exploit=result.exploit, port=self._port, output=result.output))
        return return_value
