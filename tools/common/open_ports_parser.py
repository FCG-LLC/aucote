import ipaddress
from structs import TransportProtocol, Port
import logging as log

class OpenPortsParser:
    '''
    Parsers output of nmap (also masscan) to find open ports
    '''
    def parse(self, xml, node_by_ip):
        result = []
        for host in xml.findall('host'):
            ip = ipaddress.ip_address(host.find('address').get('addr'))
            ports = host.find('ports')
            if ports is None: continue
            for xml_port in ports.findall('port'):
                state = xml_port.find('state').get('state')
                if state not in ('open', 'filtered'): continue
                port = Port()
                port.number = int(xml_port.get('portid'))
                port.transport_protocol = TransportProtocol.from_nmap_name(xml_port.get('protocol'))
                service = xml_port.find('service')
                port.service_name = service.get('name') if service is not None else None
                port.service_version = service.get('version') if service is not None else None
                port.node = node_by_ip[ip]
                log.debug('Found open port %s of %s, service is %s', port.number, str(ip), port.service_name)
                result.append(port)
        log.debug('Found %s open ports', len(result))
        return result