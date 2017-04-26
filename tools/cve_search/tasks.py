import requests
import logging as log

from aucote_cfg import cfg
from structs import Vulnerability
from tools.common.port_task import PortTask
from tools.cve_search.exceptions import CVESearchAPIException, CVESearchAPIConnectionException
from tools.cve_search.structs import CVESearchVulnerabilityResults


class CVESearchServiceTask(PortTask):
    def __init__(self, *args, **kwargs):
        self.api = cfg['tools.cve-search.api'].strip("/")
        super(CVESearchServiceTask, self).__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        if not self.port.service.cpe:
            log.warning("CVE search supports only CPE defined services")
            return

        results = self.api_cvefor(self.port.service.cpe)
        cves = CVESearchVulnerabilityResults.from_dict(results)

        vulnerabilities = self.get_vulnerabilities(cves)
        self.store_vulnerabilities(vulnerabilities)
        return results

    def api_cvefor(self, cpe):
        url = "{api}/cvefor/{cpe}".format(api=self.api, cpe=cpe.as_uri_2_3())
        try:
            response = requests.get(url)
        except requests.exceptions.ConnectionError:
            raise CVESearchAPIConnectionException()

        if response.status_code is not 200:
            raise CVESearchAPIException(response)
        return response.json()

    def get_vulnerabilities(self, results):
        return_value = []

        for result in results:
            return_value.append(Vulnerability(exploit=self.exploit, port=self._port, output=result.output))
        return return_value
