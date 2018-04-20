"""
Contains tool class for AucoteActiveDirectory

"""
import ipaddress

from async_dns import types
from async_dns.resolver import ProxyResolver

from aucote_cfg import cfg
from structs import SpecialPort, TransportProtocol
from tools.acuote_ad.bases.enum4linux_base import Enum4linuxBase
from tools.acuote_ad.tasks.aucote_ad_task import AucoteActiveDirectoryTask
from tools.acuote_ad.tasks.enum4linux_task import Enum4linuxTask
from tools.base import Tool


class AucoteActiveDirectory(Tool):
    """
    This tool provides tasks for Active Directory management

    ToDo: Push more information to kudu, when security_audits will be splitted

    """
    def __init__(self, node=None, port=None, *args, **kwargs):
        super(AucoteActiveDirectory, self).__init__(port=port, *args, **kwargs)
        self.node = node

    async def call(self, *args, **kwargs):
        dns_servers = cfg['tools.common.active-directory.dns_servers']._cfg
        domain_names = cfg['tools.common.active-directory.domains']._cfg
        username = cfg['tools.common.active-directory.username']
        password = cfg['tools.common.active-directory.password']
        exploits = [self.aucote.exploits.find('aucote-active-directory', 'enum4linux')]

        if not self.node:
            for domain_name in domain_names:
                self.context.add_task(Enum4linuxTask(domain=domain_name, username=username, password=password,
                                                     command=Enum4linuxBase(), context=self.context, scan=self._scan,
                                                     port=self._port, exploits=exploits))
            return

        if str(self.node.ip) not in dns_servers:
            return

        for domain_name in domain_names:
            nodes = set()
            for dns_server in dns_servers:
                current_nodes = self.storage.get_nodes_by_scan(self._scan)
                nodes.update(await self.resolve_nodes(dns_server=dns_server, domain_name=domain_name,
                                                      current_nodes=current_nodes))

            port = SpecialPort(node=self.node, transport_protocol=TransportProtocol.TCP)
            port.scan = self._scan

            self.context.add_task(AucoteActiveDirectoryTask(
                domain=domain_name, nodes=nodes, context=self.context, scan=self._scan, port=port, exploits=exploits))

    async def resolve_nodes(self, dns_server, domain_name, current_nodes):
        domain = "_ldap._tcp.dc._msdcs.{domain}".format(domain=domain_name)
        nodes = []
        resolver = ProxyResolver()
        resolver.set_proxies([dns_server])
        dns_result = None
        while dns_result is None:
            dns_result = await resolver.query(domain, types.SRV)

        for record in dns_result.an:
            dns_a_result = None
            while dns_a_result is None:
                dns_a_result = await resolver.query(record.data[3], types.A)
                for a_record in dns_a_result.an:
                    ip_address = ipaddress.ip_address(a_record.data)
                    for node in current_nodes:
                        if node.ip == ip_address:
                            nodes.append(node)

        return nodes

    def additional_info(self):
        return "on {port}".format(port=self.port if self.port else self.node)
