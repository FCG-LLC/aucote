"""
Contains main class responsible for managing NMAP

"""
import logging as log
from collections import defaultdict

import itertools

from aucote_cfg import cfg
from fixtures.exploits.exploit import RiskLevel
from structs import TransportProtocol
from tools.base import Tool
from tools.nmap.base import NmapScript
from tools.nmap.parsers import NmapVulnParser, NmapInfoParser
from tools.nmap.tasks.port_scan import NmapPortScanTask


class NmapTool(Tool):
    """
    It's responsible for managing and executing nmap tasks

    """
    async def call(self, *args, **kwargs):
        """
        Prepares nmap args, executes and manages nmap scripts.

        If there is a list of different arguments and this same script name, they shouldn't be executed together
        """
        tasks = self._get_tasks()

        by_name = defaultdict(set)
        for task in tasks:
            by_name[task.name].add(task)
        packs = itertools.zip_longest(*by_name.values())

        for pack in packs:
            self.context.add_task(NmapPortScanTask(context=self.context, port=self.port,
                                                   script_classes=[val for val in pack if val is not None],
                                                   rate=self.rate))

    def _get_tasks(self):
        """
        Prepare nmaps scripts  for executing

        Returns:
            list - list of tasks
        """
        tasks = []

        disabled_scripts = self.config.get('disable_scripts', set()).copy()
        disabled_scripts.update(set(cfg['tools.nmap.disable_scripts'] or []))

        for exploit in self.exploits:
            name = exploit.name

            if name in disabled_scripts:
                continue

            service_args = self.config.get('services', {}).get(self.port.protocol, {}).get('args', None)

            if callable(service_args):
                service_args = service_args()
            else:
                service_args = ""

            args = self.config.get('scripts', {}).get(name, {}).get('args', None)
            singular = self.config.get('scripts', {}).get(name, {}).get('singular', False)

            if callable(args):
                try:
                    args = args()
                except KeyError:
                    log.warning("Please set up %s in configuration", name)
                    continue

            if not isinstance(args, (list, set)):
                args = [args]

            for arg in args:
                arg = "{0},{1}".format(arg or "", service_args).strip(",")

                parser = self.config.get('scripts', {}).get(exploit.name, {}).get('parser')

                if not parser and exploit.risk_level == RiskLevel.NONE:
                    parser = NmapInfoParser
                elif not parser:
                    parser = NmapVulnParser

                task = NmapScript(exploit=exploit, port=self.port, parser=parser(), name=name, args=arg)

                if singular:
                    self.context.add_task(NmapPortScanTask(context=self.context, port=self.port,
                                                           script_classes=[task], rate=self.rate))
                    continue
                tasks.append(task)

        return tasks

    @classmethod
    def custom_args_dns_zone_transfer(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            list

        """
        domains = cfg['tools.nmap.domains']
        return ['dns-zone-transfer.domain={0}'.format(domain) for domain in domains]

    @classmethod
    def custom_args_dns_srv_enum(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            list

        """
        domains = cfg['tools.nmap.domains']
        return ['dns-srv-enum.domain={0}'.format(domain) for domain in domains]

    @classmethod
    def custom_args_dns_check_zone(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            list

        """
        domains = cfg['tools.nmap.domains']
        return ['dns-check-zone.domain={0}'.format(domain) for domain in domains]

    @classmethod
    def custom_args_http_domino_enum_passwords(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            str

        """
        username = cfg['tools.nmap.domino-http.username']
        password = cfg['tools.nmap.domino-http.password']

        return "domino-enum-passwords.username='{0}',domino-enum-passwords.password={1}".format(username, password)

    @classmethod
    def custom_args_http_useragent(cls):
        """
        Parses configuration and convert it to the script argument

        Returns:
            str

        """
        config = cfg['tools.common.http.useragent']
        if config:
            return "http.useragent='{0}'".format(config)

    @property
    def rate(self):
        """
        Rate for Nmap scripts

        Returns:
            int

        """
        try:
            return cfg['tools.nmap.rate']
        except KeyError:
            return cfg['tools.common.rate']

    @staticmethod
    def parse_nmap_ports(port_string):
        """
        Parses nmap ports argument and returns dictionary of sets

        Args:
            port_string (str):

        Returns:
            dict

        """

        return_value = {
            "T": set(),
            "U": set(),
            "S": set()
        }

        sections = port_string.split(",")

        protocol = "T"

        for section in sections:
            if ":" in section:
                protocol = section[0]
                section = section[2:]

            return_value[protocol] |= NmapTool.parse_ports_string(section)

        return {
            TransportProtocol.TCP: return_value["T"],
            TransportProtocol.UDP: return_value["U"],
            TransportProtocol.SCTP: return_value["S"]
        }

    @staticmethod
    def parse_ports_string(text):
        """
        Parses port string (standalone number or range) and returns as set

        Args:
            text (str):

        Returns:
            set

        """
        if "-" in text:
            range_args = [int(el) for el in text.split("-")]
            return set(range(range_args[0], range_args[1]+1))

        return {int(text)}

    @staticmethod
    def ports_from_list(tcp=None, udp=None, sctp=None):
        """
        Returns dict of ports by protocol based on given lists of ports

        Args:
            tcp (list):
            udp (list):
            sctp (list):

        Returns:
            dict

        """
        return_value = {
            TransportProtocol.TCP: set(),
            TransportProtocol.UDP: set(),
            TransportProtocol.SCTP: set()
        }

        tcp = map(str, tcp or [])
        udp = map(str, udp or [])
        sctp = map(str, sctp or [])

        for port in tcp:
            return_value[TransportProtocol.TCP] |= NmapTool.parse_ports_string(port)

        for port in udp:
            return_value[TransportProtocol.UDP] |= NmapTool.parse_ports_string(port)

        for port in sctp:
            return_value[TransportProtocol.SCTP] |= NmapTool.parse_ports_string(port)

        return return_value

    @staticmethod
    def list_to_ports_string(tcp=None, udp=None, sctp=None):
        """
        Convert list of ports to Nmap format

        Args:
            self:
            tcp (list|Config):
            udp (list|Config):
            sctp (list|Config):

        Returns:
            str

        """
        ports = []

        if tcp:
            ports.append("T:{0}".format(",".join(map(str, tcp))))

        if udp:
            ports.append("U:{0}".format(",".join(map(str, udp))))

        if sctp:
            ports.append("S:{0}".format(",".join(map(str, sctp))))

        return ",".join(ports)

    @classmethod
    def custom_args_smb(cls):
        domain_names = cfg['tools.common.active-directory.domains'].cfg
        username = cfg['tools.common.active-directory.username']
        password = cfg['tools.common.active-directory.password']

        if not all([domain_names, username, password]):
            return ""

        return ["smbusername='{0}',smbpassword='{1}',smbdomain='{2}'".format(username, password, domain) for domain in domain_names]
