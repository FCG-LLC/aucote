"""
Handler abstract class
"""
import hashlib

from tornado.web import RequestHandler

from aucote_cfg import cfg
from utils.time import parse_timestamp_to_time


class Handler(RequestHandler):
    """
    Defines common properties for handler

    """
    SCANNER_URL = "/api/v1/scanner/{scanner_name}"
    SCAN_URL = '/api/v1/scan/{scan_id}'
    NODES_SCAN_URL = '/api/v1/node/{node_scan_id}'
    PORTS_SCAN_URL = '/api/v1/port/{port_scan_id}'
    SECURITY_SCAN_URL = '/api/v1/sec_scan/{sec_scan_id}'
    VULNERABILITY_URL = '/api/v1/vulnerability/{vuln_id}'

    def initialize(self, aucote):
        """
        Integrates Handlers with aucote

        Args:
            aucote (Aucote):

        Returns:
            None

        """
        self.aucote = aucote

    @staticmethod
    def auth(handler_class):
        """
        Handler for authorization

        Args:
            handler_class:

        Returns:

        """
        MAX_PASSWORD_HEADER_LENGTH = 80
        BEARER_START = 'Bearer '

        def wrap_execute(handler_execute):
            """
            Authorize request

            Args:
                handler_execute:

            Returns:

            """
            def require_auth(handler, *args, **kwargs):
                """
                Authorize request

                Args:
                    handler:
                    *args:
                    **kwargs:

                Returns:
                    bool

                """
                auth_header = handler.request.headers.get('Authorization')

                if auth_header is not None and len(auth_header) < MAX_PASSWORD_HEADER_LENGTH \
                        and auth_header.startswith(BEARER_START):
                    password = auth_header[len(BEARER_START):]
                    password_hash = hashlib.sha512(password.encode()).hexdigest()
                    correct = cfg['service.api.password']

                    if password_hash == correct:
                        return True

                handler.set_status(401)
                handler._transforms = []
                handler.finish()
                return False

            def _execute(self, transforms, *args, **kwargs):
                if not require_auth(self, kwargs):
                    return False
                return handler_execute(self, transforms, *args, **kwargs)

            return _execute

        handler_class._execute = wrap_execute(handler_class._execute)
        return handler_class

    @staticmethod
    def limit(function):
        def return_value(self, *args, **kwargs):
            for key in ('limit', 'page'):
                value = self.get_query_arguments(key)

                if value and value[0].isdecimal():
                    kwargs[key] = int(value[0])

            return function(self, *args, **kwargs)

        return return_value

    def format_url(self, url):
        return "{0}://{1}{2}".format(self.request.protocol, self.request.host, url)

    def url_scanner(self, scanner_name):
        return self.format_url(self.SCANNER_URL.format(scanner_name=scanner_name))

    def url_scan(self, scan_id):
        return self.format_url(self.SCAN_URL.format(scan_id=scan_id))

    def url_nodes_scan(self, node_scan_id):
        return self.format_url(self.NODES_SCAN_URL.format(node_scan_id=node_scan_id))

    def url_ports_scan(self, port_scan_id):
        return self.format_url(self.PORTS_SCAN_URL.format(port_scan_id=port_scan_id))

    def url_security_scan(self, sec_scan_id):
        return self.format_url(self.SECURITY_SCAN_URL.format(sec_scan_id=sec_scan_id))

    def url_vulnerability(self, vuln_id):
        return self.format_url(self.VULNERABILITY_URL.format(vuln_id=vuln_id))

    def pretty_scan(self, scan):
        """

        Args:
            scan (Scan):

        Returns:

        """
        return {
            "id": scan.rowid,
            "url": self.url_scan(scan.rowid),
            "start": scan.start,
            "start_human": parse_timestamp_to_time(scan.start),
            "end": scan.end,
            "end_human": parse_timestamp_to_time(scan.end) if scan.end is not None else None,
            "protocol": scan.protocol.db_val if scan.protocol else None,
            "scanner": scan._scanner,
            "scanner_url": self.url_scanner(scan._scanner)
        }

    def pretty_node(self, node_scan):
        """

        Args:
            node (Node):

        Returns:

        """
        return {
            "id": node_scan.rowid,
            "url": self.url_nodes_scan(node_scan.rowid),
            "node_id": node_scan.node.id,
            "ip": str(node_scan.node.ip),
            "scan": node_scan.scan.rowid,
            "scan_url": self.url_scan(node_scan.scan.rowid)
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
            'url': self.url_ports_scan(port_scan.rowid),
            'port': self.pretty_port(port_scan.port),
            'timestamp': port_scan.timestamp,
            'timestamp_human': parse_timestamp_to_time(port_scan.timestamp),
            "scan": port_scan.scan.rowid,
        }

    def pretty_port(self, port):
        return {
            'port_number': port.number,
            'protocol': port.transport_protocol.db_val,
            'node': {
                'id': port.node.id,
                'ip': str(port.node.ip)
            }
        }
