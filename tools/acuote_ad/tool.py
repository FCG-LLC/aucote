"""
Contains tool class for AucoteActiveDirectory

"""
import ipaddress

from async_dns import types
from async_dns.resolver import ProxyResolver

from aucote_cfg import cfg
from structs import SpecialPort
from tools.acuote_ad.bases.enum4linux_base import Enum4linuxBase
from tools.acuote_ad.tasks.enum4linux_task import Enum4linuxTask
from tools.base import Tool


class AucoteActiveDirectory(Tool):
    """
    This tool provides tasks for Active Directory management

    """
    async def call(self, *args, **kwargs):
        dns_server = cfg['tools.aucote-active-directory.config.dns_server']
        domain_name = cfg['tools.aucote-active-directory.config.domain']
        domain = "_ldap._tcp.dc._msdcs.{domain}".format(domain=cfg['tools.aucote-active-directory.config.domain'])
        username = cfg['tools.aucote-active-directory.config.username']
        password = cfg['tools.aucote-active-directory.config.password']

        resolver = ProxyResolver()
        resolver.set_proxies([dns_server])
        dns_result = None
        while dns_result is None:
            dns_result = await resolver.query(domain, types.SRV)

        nodes = []
        current_nodes = self.storage.get_nodes_by_scan(self._scan)

        for record in dns_result.an:
            dns_a_result = None
            while dns_a_result is None:
                dns_a_result = await resolver.query(record.data[3], types.A)
                for a_record in dns_a_result.an:
                    ip_address = ipaddress.ip_address(a_record.data)
                    for node in current_nodes:
                        if node.ip == ip_address:
                            nodes.append(node)

        for node in nodes:
            port = SpecialPort(node=node)
            self.aucote.add_async_task(Enum4linuxTask(domain=domain_name, username=username, password=password,
                                                      command=Enum4linuxBase(), aucote=self.aucote, scan=self._scan,
                                                      port=port, exploits=[]))

