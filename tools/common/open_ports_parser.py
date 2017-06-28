"""
Provides parser for open ports

"""
import ipaddress
import logging as log
from structs import TransportProtocol, Port, Scan, PortState


class OpenPortsParser:
    """
    Parsers output of nmap (also masscan) to find open ports

    """
    @classmethod
    def parse(cls, xml, node_by_ip):
        """
        Gets Element Tree objects and based on it, creates Ports collection

        Args:
            xml (ElementTree.Element):
            node_by_ip (dict):

        Returns:
            list

        """
        result = []
        for host in xml.findall('host'):
            ip = ipaddress.ip_address(host.find('address').get('addr'))
            ports = host.find('ports')
            if ports is None:
                continue
            for xml_port in ports.findall('port'):
                state = PortState[xml_port.find('state').get('state').upper()]
                if state not in (PortState.OPEN, PortState.FILTERED, PortState.OPEN_FILTERED):
                    continue

                number = int(xml_port.get('portid'))
                transport_protocol = TransportProtocol.from_nmap_name(xml_port.get('protocol'))
                node = node_by_ip[ip]

                port = Port(number=number, node=node, transport_protocol=transport_protocol)
                port.scan = Scan(start=node.scan.start)

                service = xml_port.find('service')
                port.service_name = service.get('name') if service is not None else None
                port.service_version = service.get('version') if service is not None else None

                log.debug('Found open port %s of %s, service is %s', port.number, str(ip), port.service_name)

                for script in xml_port.findall('script'):
                    if script.get('id') == 'banner':
                        port.banner = script.get('output')
                        break

                result.append(port)
        log.info('Found %s open ports', len(result))
        return result
