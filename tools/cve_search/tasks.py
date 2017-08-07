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
from structs import Vulnerability, Port, PhysicalPort
from tools.common.port_task import PortTask
from tools.cve_search.exceptions import CVESearchAPIException, CVESearchAPIConnectionException
from tools.cve_search.parsers import CVESearchParser
from utils.http_client import HTTPClient


class CVESearchServiceTask(PortTask):
    """
    Task which proceed port service and asks CVE server for CVEs

    """
    VENDOR_APACHE = 'apache'
    APACHE_HTTPD = 'httpd'
    APACHE_HTTP_SERVER = 'http_server'

    def __init__(self, *args, **kwargs):
        self.api = cfg['tools.cve-search.api'].strip("/")
        super(CVESearchServiceTask, self).__init__(*args, **kwargs)

    async def __call__(self, *args, **kwargs):
        cpes = self.get_cpes()
        if not cpes:
            return
        result = []
        for cpe in cpes:
            try:
                result.extend(await self.api_cvefor(cpe))
            except CVESearchAPIConnectionException:
                log.warning("Error during connection to cve-search server")

        if not result:
            return
        cves = CVESearchParser.dict_to_results(result)

        self.store_vulnerability(Vulnerability(exploit=self.exploit, port=self._port, output=cves.output))

    def get_cpes(self):
        """
        Get cpe based on port service

        Returns:
            list - list of CPEs

        """
        cpes = []
        return_value = []

        if self.port.apps:
            cpes = [app.cpe for app in self.port.apps]
        elif isinstance(self.port, PhysicalPort):
            cpes = [self.port.node.os.cpe]
        elif isinstance(self.port, Port):
            cpes = [self.port.service.cpe]

        for cpe in self._unique_cpes(cpes):
            if not cpe.get_version()[0]:
                log.debug("CVE search: CPE without version is not supported")
                continue

            if cpe.get_vendor()[0] == self.VENDOR_APACHE:
                if cpe.get_product()[0] == self.APACHE_HTTPD:
                    return_value.extend([cpe, CPE(cpe.as_uri_2_3().replace(self.APACHE_HTTPD,
                                                                           self.APACHE_HTTP_SERVER))])
                    continue
                elif cpe.get_product()[0] == self.APACHE_HTTP_SERVER:
                    return_value.extend([cpe, CPE(cpe.as_uri_2_3().replace(self.APACHE_HTTP_SERVER,
                                                                           self.APACHE_HTTPD))])
                    continue

            return_value.append(cpe)

        return self._unique_cpes(return_value)

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
            if cpe is not None and cpe not in return_value:
                return_value.append(cpe)
        return return_value

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
        except HTTPError as exception:
            raise CVESearchAPIConnectionException(str(exception))
        except ConnectionError as exception:
            raise CVESearchAPIConnectionException(str(exception))

        if response.code is not 200:
            raise CVESearchAPIException(response)
        return ujson.loads(response.body.decode())

    def get_vulnerabilities(self, results):
        return [Vulnerability(exploit=self.exploit, port=self._port, output=result.output) for result in results]
