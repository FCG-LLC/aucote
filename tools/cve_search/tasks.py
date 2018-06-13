"""
Tasks related to cve-search module

"""
import logging as log
import re

from urllib.parse import quote
import ujson

from cpe import CPE
from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from structs import Vulnerability, PhysicalPort, Port
from tools.common.port_task import PortTask
from tools.cve_search.exceptions import CVESearchApiException
from tools.cve_search.parsers import CVESearchParser
from utils.http_client import HTTPClient, retry_if_fail


class CVESearchServiceTask(PortTask):
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
        self.api = cfg['tools.cve-search.api'].strip("/")
        super(CVESearchServiceTask, self).__init__(*args, **kwargs)

    async def execute(self, *args, **kwargs):
        cpes = self.get_cpes()
        if not cpes:
            return
        result = []
        for cpe in cpes:
            try:
                result.extend(await self.api_cvefor(cpe))
            except CVESearchApiException:
                log.warning("Error during connection to cve-search server")

        if not result:
            return
        cves = CVESearchParser.dict_to_results(result)

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
            if not cpe.get_version()[0]:
                log.debug("CVE search: CPE without version is not supported")
                continue

            if cpe.get_vendor()[0] == self.VENDOR_APACHE:
                if cpe.get_product()[0] == self.APACHE_HTTPD:
                    detailed_cpes.extend([cpe, CPE(cpe.as_uri_2_3().replace(self.APACHE_HTTPD,
                                                                            self.APACHE_HTTP_SERVER))])
                    continue
                elif cpe.get_product()[0] == self.APACHE_HTTP_SERVER:
                    detailed_cpes.extend([cpe, CPE(cpe.as_uri_2_3().replace(self.APACHE_HTTP_SERVER,
                                                                            self.APACHE_HTTPD))])
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
                   exceptions=CVESearchApiException)
    async def api_cvefor(self, cpe):
        """
        Get list of CVES from cve-search API

        to be suit with cve-search, we need to strip slashes and replace %28 to %252528 (%28 -> %2528 -> %252528)

        Args:
            cpe (CPE):

        Returns:
            list

        """
        cpe_encoded = re.sub('%2([89])', r'%25252\1', quote(cpe.as_fs().replace('\\', '')))
        url = "{api}/cvefor/{cpe}".format(api=self.api, cpe=cpe_encoded)
        try:
            response = await HTTPClient.instance().get(url)
        except (HTTPError, ConnectionError) as exception:
            raise CVESearchApiException(str(exception))

        return ujson.loads(response.body.decode())

    def get_vulnerabilities(self, results):
        return [Vulnerability(exploit=self.exploit, port=self._port, output=result.summary, scan=self._scan,
                              context=self.context, cve=result.cve, cvss=result.cvss, subid=subid)
                for subid, result in enumerate(results)]
