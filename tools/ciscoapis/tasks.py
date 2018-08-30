"""
Tasks related to cve-search module

"""
import logging as log
import ujson

from cpe import CPE
from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from structs import Vulnerability, PhysicalPort, Port
from tools.ciscoapis.exceptions import CiscoApiException
from tools.ciscoapis.parsers import PsirtParser
from tools.ciscoapis.structs import PsirtResults
from tools.common.port_task import PortTask
from utils.http_client import HTTPClient, retry_if_fail


class CiscoApisPsirtTask(PortTask):
    """
    Task which proceed port service and asks CVE server for CVEs

    """
    VENDOR_APACHE = 'apache'
    APACHE_HTTPD = 'httpd'
    APACHE_HTTP_SERVER = 'http_server'
    MAX_RETRIES = 3
    MIN_RETRY_TIME = 10
    MAX_RETRY_TIME = 120

    def __init__(self, *args, **kwargs):
        self.api = cfg['tools.ciscoapis.api'].strip("/")
        super().__init__(*args, **kwargs)

    async def execute(self, *args, **kwargs):
        cpes = self.get_cpes()
        if not cpes:
            return
        result = []
        for cpe in cpes:
            try:
                result.extend(await self.api_psirt(cpe))
            except CiscoApiException:
                log.warning("Error during connection to ciscoapi server")

        if not result:
            return
        cves = PsirtParser.dict_to_results(result)

        for vulnerability in self.get_vulnerabilities(cves.vulnerabilities):
            self.store_vulnerability(vulnerability)

    def get_cpes(self):
        """
        Get cpe based on port service

        Returns:
            list - list of CPEs

        """
        cpes = []
        detailed_cpes = []

        if self.port.apps:
            cpes = [app.cpe for app in self.port.apps if app.cpe is not None]
        elif isinstance(self.port, PhysicalPort) and self.port.node.os.cpe is not None:
            cpes = [self.port.node.os.cpe]
        elif isinstance(self.port, Port) and self.port.service.cpe is not None:
            cpes = [self.port.service.cpe]

        for cpe in self._unique_cpes(cpes):
            if cpe.get_vendor() != ['cisco'] or cpe.get_product() != ['ios']:
                continue

            if not cpe.get_version()[0]:
                log.debug("Ciscoapis: CPE without version is not supported")
                continue

            detailed_cpes.append(cpe)

        return self._unique_cpes(detailed_cpes)

    def _unique_cpes(self, cpes):
        """
        Return list of unique cpes

        Args:
            cpes (list):

        Returns:
            list

        """
        return_value = []
        for cpe in cpes:
            if cpe not in return_value:
                return_value.append(cpe)
        return return_value

    @retry_if_fail(min_retry_time=MIN_RETRY_TIME, max_retry_time=MAX_RETRY_TIME, max_retries=MAX_RETRIES,
                   exceptions=CiscoApiException)
    async def api_psirt(self, cpe: CPE) -> list:
        """
        Get list of CVES from cve-search API

        to be suit with cve-search, we need to strip slashes and replace %28 to %252528 (%28 -> %2528 -> %252528)

        Args:
            cpe (CPE):
        """
        url = "{api}/psirt/by_product/{version}".format(api=self.api, version=cpe.get_version()[0]
                                                        .replace('\\(', '(')
                                                        .replace('\\)', ')').upper())
        try:
            response = await HTTPClient.instance().get(url, request_timeout=120)
        except (HTTPError, ConnectionError) as exception:
            raise CiscoApiException(str(exception))

        return ujson.loads(response.body.decode())

    def get_vulnerabilities(self, results: PsirtResults):
        """
        Ciscoapis could be run multiple times during one scan by different scripts, so duplicated vulnerabilities
        should be filtered out.

        Filtering is executed against vulnerabilities already stored in storage
        """
        current_scan_vulns = self.storage.get_vulnerabilities(port=self._port, scan=self.scan, exploit=self.exploit)

        next_subid = max([-1, *[vuln.subid for vuln in current_scan_vulns]]) + 1
        cves = [vuln.cve for vuln in current_scan_vulns]

        return_value = []

        for result in results:
            # Omit vulnerability with the same CVE found in current scan
            if result.cve in cves:
                log.debug('%s:(%s) vulnerability already discovered for %s', self.exploit, result.cve, self._port)
                continue

            return_value.append(Vulnerability(exploit=self.exploit, port=self._port, output=result.summary,
                                              scan=self.scan, context=self.context, cve=result.cve, cvss=result.cvss,
                                              subid=next_subid))
            next_subid += 1

        return return_value
