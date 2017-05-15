"""
Tasks related to cve-search module

"""
from urllib import parse

import requests
import logging as log

from aucote_cfg import cfg
from structs import Vulnerability, Port, PhysicalPort
from tools.common.port_task import PortTask
from tools.cve_search.exceptions import CVESearchAPIException, CVESearchAPIConnectionException
from tools.cve_search.structs import CVESearchVulnerabilityResults


class CVESearchServiceTask(PortTask):
    """
    Task which proceed port service and asks CVE server for CVEs

    """
    def __init__(self, *args, **kwargs):
        self.api = cfg['tools.cve-search.api'].strip("/")
        super(CVESearchServiceTask, self).__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        cpe = self.get_cpe()
        if not cpe:
            return

        results = self.api_cvefor(cpe)
        if not results:
            return
        cves = CVESearchVulnerabilityResults.from_dict(results)

        self.store_vulnerability(Vulnerability(exploit=self.exploit, port=self._port, output=cves.output))

    def get_cpe(self):
        """
        Get cpe based on port service

        Returns:
            CPE

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

        return cpe

    def api_cvefor(self, cpe):
        """
        Get list of CVES from cve-search API

        Args:
            cpe (CPE):

        Returns:
            list

        """
        cpe_encoded = cpe.as_uri_2_3().replace('%', '%2525')
        url = "{api}/cvefor/{cpe}".format(api=self.api, cpe=cpe_encoded)
        try:
            response = requests.get(url)
        except requests.exceptions.ConnectionError:
            raise CVESearchAPIConnectionException()

        if response.status_code is not 200:
            raise CVESearchAPIException(response)
        return response.json()
