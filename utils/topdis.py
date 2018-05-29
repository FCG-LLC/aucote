"""
Topdis is a topology discovery tool. This file provide integration with it

"""
import logging as log
import ujson

import ipaddress

from structs import Node, Scan, TopisOSDiscoveryType, Service, CPEType
from utils.http_client import retry_if_fail, HTTPClient
from tornado.httpclient import HTTPError

from utils.time import parse_time_to_timestamp


class Topdis(object):
    """
    Topdis provides topology information which are base for all scans

    """
    min_retry_time = 5
    max_retry_time = 30
    max_retry_count = 20

    def __init__(self, hostname, port, api):
        self.api = 'http://{0}:{1}{2}'.format(hostname, port, api)

    @retry_if_fail(min_retry_time, max_retry_time, max_retry_count, HTTPError)
    async def get_nodes(self) -> set:
        """
        Get nodes from Topdis

        Returns:
            set of unique nodes (Node object)

        """
        url = '{0}/nodes?ip=t'.format(self.api)
        resource = await HTTPClient.instance().get(url)

        nodes_cfg = ujson.loads(resource.body)

        timestamp = parse_time_to_timestamp(nodes_cfg['meta']['requestTime'])
        ip_node = {}

        for node_struct in nodes_cfg['nodes']:
            for node_ip in node_struct['ips']:
                node = Node(ip=ipaddress.ip_address(node_ip), node_id=node_struct['id'])
                node.name = node_struct['displayName']
                node.scan = Scan(start=timestamp)

                software = node_struct.get('software', {})
                os = software.get('os', {})

                if os.get('discoveryType') in (TopisOSDiscoveryType.DIRECT.value,):
                    node.os.name, node.os.version = os.get('name'), os.get('version')

                    try:
                        node.os.cpe = Service.build_cpe(product=node.os.name, version=node.os.version, part=CPEType.OS)
                    except:
                        node.os.cpe = None
                ip_node[node.ip] = node

        nodes = set(ip_node.values())

        log.debug('Got %i nodes from topdis', len(nodes))
        return nodes
