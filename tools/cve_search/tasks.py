"""
Tasks related to cve-search module

"""
import logging as log

import ujson

from cpe import CPE
from tornado.httpclient import HTTPError

from aucote_cfg import cfg
from structs import Vulnerability, Port, PhysicalPort
from tools.common.port_task import PortTask
from tools.cve_search.exceptions import CVESearchAPIException, CVESearchAPIConnectionException
from tools.cve_search.parsers import CVESearchParser
from tools.cve_search.structs import CVESearchVulnerabilityResults
from utils.http_client import HTTPClient


class CVESearchServiceTask(PortTask):
    """
    Task which proceed port service and asks CVE server for CVEs

    """
    def __init__(self, *args, **kwargs):
        self.api = cfg['tools.cve-search.api'].strip("/")
        super(CVESearchServiceTask, self).__init__(*args, **kwargs)

    async def __call__(self, *args, **kwargs):
        cpes = self.get_cpes()
        if not cpes:
            return
        result = []
        for cpe in cpes:
            result.extend(await self.api_cvefor(cpe))

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
        cpe = None

        if isinstance(self.port, PhysicalPort):
            cpe = self.port.node.os.cpe
        elif isinstance(self.port, Port):
            cpe = self.port.service.cpe

        if not cpe:
            log.debug("CVE search: CPE is not defined")
            return

        if not cpe.get_version()[0]:
            log.debug("CVE search: CPE without version is not supported")
            return

        if cpe.get_vendor()[0] == 'apache':
            if cpe.get_product()[0] == 'httpd':
                return [cpe, CPE(cpe.as_uri_2_3().replace("httpd", "http_server"))]
            elif cpe.get_product()[0] == 'http_server':
                return [cpe, CPE(cpe.as_uri_2_3().replace("http_server", "httpd"))]

        return [cpe]

    async def api_cvefor(self, cpe):
        """
        Get list of CVES from cve-search API

        Args:
            cpe (CPE):

        Returns:
            list

        """
        cpe_encoded = cpe.as_fs().replace('%', '%2525')
        url = "{api}/cvefor/{cpe}".format(api=self.api, cpe=cpe_encoded)
        try:
            response = await HTTPClient.instance().get(url)
        except HTTPError:
            raise CVESearchAPIConnectionException()
        except ConnectionError:
            raise CVESearchAPIConnectionException()

        if response.code is not 200:
            raise CVESearchAPIException(response)
        return ujson.loads(response.body.decode())

    def get_vulnerabilities(self, results):
        return_value = []

        for result in results:
            return_value.append(Vulnerability(exploit=self.exploit, port=self._port, output=result.output))
        return return_value
