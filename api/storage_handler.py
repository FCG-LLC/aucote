"""
Base module for all storage related endpoints

"""

import time

from api.handler import Handler
from utils.time import parse_timestamp_to_time


class StorageHandler(Handler):
    ENDPOINT_NAME = None
    LIST_URL = '/api/v1/{name}?limit={limit}&page={page}'

    @Handler.limit
    def get(self, rowid=None, limit=10, page=0):
        """
        Handle get method and returns details if rowid is not None, else return list of objects basing on limit and page
        arguments

        Returns:
            None - writes aucote status in JSON

        """
        if not rowid:
            result = self.list(limit, page)
            result['navigation'] = {
                'limit': limit,
                'page': page,
                'next_page': self.url_list(limit, page + 1),
                'previous_page': self.url_list(limit, page - 1 if page > 0 else 0)
            }
        else:
            result = self.details(int(rowid))

        timestamp = time.time()

        result['meta'] = {
            'timestamp': timestamp,
            'human_timestamp': parse_timestamp_to_time(timestamp)
        }
        self.write(result)

    def list(self, limit, page):
        """
        This function returns list of objects basing on storage

        Args:
            limit (int):
            page (int):

        Returns:
            list

        """
        raise NotImplementedError

    def details(self, rowid):
        """
        Returns object from storage basing on given id

        Args:
            rowid (int):

        Returns:
            None

        """
        raise NotImplementedError

    def url_list(self, limit, page):
        return self._format_url(self.LIST_URL.format(name=self.ENDPOINT_NAME, limit=limit, page=page))

    def _format_url(self, url, **kwargs):
        return '{0}://{1}{2}'.format(self.request.protocol, self.request.host, url).format(**kwargs)

    def _url_scanner(self, scanner_name):
        return self._format_url(self.SCANNER_URL, scanner_name=scanner_name)

    def _url_scan(self, scan_id):
        return self._format_url(self.SCAN_URL, scan_id=scan_id)

    def _url_nodes_scan(self, node_scan_id):
        return self._format_url(self.NODES_SCAN_URL, node_scan_id=node_scan_id)

    def _url_ports_scan(self, port_scan_id):
        return self._format_url(self.PORTS_SCAN_URL, port_scan_id=port_scan_id)

    def _url_security_scan(self, sec_scan_id):
        return self._format_url(self.SECURITY_SCAN_URL, sec_scan_id=sec_scan_id)

    def _url_vulnerability(self, vuln_id):
        return self._format_url(self.VULNERABILITY_URL, vuln_id=vuln_id)

    def pretty_scan(self, scan):
        """

        Args:
            scan (Scan):

        Returns:

        """
        return {
            'id': scan.rowid,
            'url': self._url_scan(scan.rowid),
            'start': scan.start,
            'start_human': parse_timestamp_to_time(scan.start),
            'end': scan.end,
            'end_human': parse_timestamp_to_time(scan.end) if scan.end is not None else None,
            'protocol': scan.protocol.db_val if scan.protocol else None,
            'scanner': scan._scanner,
        }

    def pretty_node(self, node_scan):
        """

        Args:
            node (Node):

        Returns:

        """
        return {
            'id': node_scan.rowid,
            'url': self._url_nodes_scan(node_scan.rowid),
            'node_id': node_scan.node.id,
            'ip': str(node_scan.node.ip),
            'scan': node_scan.scan.scanner
        }

    def pretty_port_scan(self, port_scan):
        """

        Args:
            port_scan (PortScan):

        Returns:
            PortScan
        """
        return {
            'id': port_scan.rowid,
            'url': self._url_ports_scan(port_scan.rowid),
            'port': self.pretty_port(port_scan.port),
            'timestamp': port_scan.timestamp,
            'timestamp_human': parse_timestamp_to_time(port_scan.timestamp),
            'scan': port_scan.scan.scanner
        }

    def pretty_port(self, port):
        return {
            'port_number': port.number,
            'protocol': port.transport_protocol.db_val,
            'node': str(port.node)
        }
