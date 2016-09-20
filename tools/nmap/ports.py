from .base import NmapBase
from structs import Port, TransportProtocol
import logging as log
import ipaddress

class PortsScan(NmapBase):
    '''
    This class is deprecated
    '''

    def scan_ports(self, nodes, ports=None):
        node_by_ip = {str(node.ip): node for node in nodes}
        result = []   
        args = list(self.COMMON_ARGS)
        if ports is None:
            args.extend(('-p', '0-65535'))
        else:
            port_str = ','.join([str(port) for port in ports])
            args.extend(('-p', port_str))
        args.extend( ('-sV', '--script', 'banner') )
        args.extend([str(node.ip) for node in nodes])
        xml = self.call(args)
        for host in xml.findall('host'):
            ip = ipaddress.ip_address(host.find('address').get('addr'))
            ports = host.find('ports')
            if ports is None: continue
            for port in ports.findall('port'):
                state = port.find('state').get('state')
                if state not in ('open', 'filtered'): continue
                port_id = int(port.get('portid'))
                port_protocol = port.get('protocol')
                service = port.find('service')
                service_name = service.get('name') if service is not None else None
                service_version = service.get('version') if service is not None else None
                log.debug('Found open port %s of %s, service is %s', port_id, str(ip), service_name)
                banner = None
                for script in port.findall('script'):
                    if script.get('id') == 'banner':
                        banner = script.get('output')

                port = Port(transport_protocol=TransportProtocol.from_nmap_name(port_protocol), number=port_id,
                            node=node_by_ip[str(ip)])

                port.service_name = service_name
                port.service_version = service_version
                port.banner = banner

                result.append(port)
        return result
