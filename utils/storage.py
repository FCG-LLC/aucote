"""
This file contains class for storage temporary information like last date of scanning port
"""
import ipaddress
import sqlite3
import time
import logging as log
import uuid

from math import ceil

from aucote_cfg import cfg
from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan, Vulnerability, PortScan, SecurityScan, NodeScan
from utils.database_interface import DbInterface
from scans.tcp_scanner import TCPScanner
from scans.udp_scanner import UDPScanner


class Storage(DbInterface):
    """
    This class provides local storage functionality

    """
    TABLES = {
        'scans': {
            'columns': ['rowid', 'protocol', 'scanner_name', 'scan_start', 'scan_end'],
            'factor': '_scan_from_row',
            'order': 'ORDER BY scan_start DESC, scan_end DESC'
        },
        'nodes_scans': {
            'columns': ['rowid', 'node_id', 'node_ip', 'scan_id', 'time'],
            'factor': '_nodes_scan_from_row',
            'order': 'ORDER BY time DESC'
        },
        'ports_scans': {
            'columns': ['rowid', 'node_id', 'node_ip', 'scan_id', 'port', 'port_protocol', 'time'],
            'factor': '_port_scan_from_row',
            'order': 'ORDER BY time DESC'
        },
        'security_scans': {
            'columns': ['rowid', 'scan_id', 'exploit_id', 'exploit_app', 'exploit_name', 'node_id', 'node_ip',
                        'port_protocol', 'port_number', 'sec_scan_start', 'sec_scan_end'],
            'factor': '_sec_scan_from_row',
            'order': 'ORDER BY sec_scan_end DESC, sec_scan_start DESC'
        },
        'vulnerabilities': {
            'columns': ['rowid', 'scan_id', 'node_id', 'node_ip', 'port_protocol', 'port', 'vulnerability_id',
                        'vulnerability_subid', 'cve', 'cvss', 'output', 'time'],
            'factor': '_vulnerability_from_row',
            'order': 'ORDER BY time DESC'
        },
    }

    SELECT_QUERY = "SELECT {columns} FROM {table} {join} {where} {order} {limit}"

    GET_LAST_ROWID = "SELECT last_insert_rowid()"

    CREATE_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS scans(protocol int, scanner_name str, scan_start int, "\
                         "scan_end int, UNIQUE (protocol, scanner_name, scan_start))"
    SAVE_SCAN_QUERY = "INSERT INTO scans (protocol, scanner_name, scan_start, scan_end) VALUES (?, ?, ?, ?)"
    UPDATE_SCAN_END_QUERY = "UPDATE scans set scan_end = ? WHERE ROWID=?"

    CREATE_NODES_TABLE = "CREATE TABLE IF NOT EXISTS nodes_scans(scan_id int, node_id int, node_ip text, time int, " \
                         "primary key (scan_id, node_id, node_ip))"
    SAVE_NODE_QUERY = "INSERT INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (?, ?, ?, ?)"

    CREATE_PORTS_TABLE = "CREATE TABLE IF NOT EXISTS ports_scans (scan_id int, node_id int, node_ip text, port int, " \
                         "port_protocol int, time int, primary key (scan_id, node_id, node_ip, port, port_protocol))"
    SAVE_PORT_QUERY = "INSERT INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) "\
                      "VALUES (?, ?, ?, ?, ?, ?)"

    CREATE_SECURITY_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS security_scans (scan_id int, exploit_id int, " \
                                  "exploit_app text, exploit_name text, node_id int, node_ip text, port_protocol int, "\
                                  "port_number int, sec_scan_start float, sec_scan_end float, PRIMARY KEY (scan_id, "\
                                  "exploit_id, node_id, node_ip, port_protocol, port_number))"
    SAVE_SECURITY_SCAN_DETAIL = "INSERT OR IGNORE INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name,"\
                                " node_id, node_ip, port_protocol, port_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    SAVE_SECURITY_SCAN_DETAIL_START = "UPDATE security_scans SET sec_scan_start=? WHERE exploit_id=? AND "\
                                      "exploit_app=? AND exploit_name=? AND node_id=? AND node_ip=? AND "\
                                      "(port_protocol=? OR (? IS NULL AND port_protocol IS NULL)) AND port_number=? "\
                                      "AND scan_id=?"
    SAVE_SECURITY_SCAN_DETAIL_END = "UPDATE security_scans SET sec_scan_end=? WHERE exploit_id=? AND exploit_app=? " \
                                    "AND exploit_name=? AND node_id=? AND node_ip=? AND (port_protocol=? OR (? IS NULL"\
                                    " AND port_protocol IS NULL)) AND port_number=? AND scan_id=?"
    CLEAR_SECURITY_SCANS = "DELETE FROM security_scans WHERE sec_scan_start >= sec_scan_end OR sec_scan_start IS NULL "\
                           "OR sec_scan_end IS NULL"

    SAVE_SECURITY_SCAN = "INSERT INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name,"\
                                " node_id, node_ip, port_protocol, port_number, sec_scan_start, sec_scan_end) " \
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

    CREATE_VULNERABILITIES_TABLE = "CREATE TABLE IF NOT EXISTS vulnerabilities(scan_id int, node_id int, node_ip int, "\
                                   "port_protocol int, port int, vulnerability_id int, vulnerability_subid int, "\
                                   "cve text, cvss text, output text, time int, primary key(scan_id, node_id, "\
                                   "node_ip, port_protocol, port, vulnerability_subid))"
    SAVE_VULNERABILITY = "INSERT INTO vulnerabilities (scan_id, node_id, node_ip, port_protocol, port, " \
                         "vulnerability_id, vulnerability_subid, cve, cvss, output, time) " \
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

    CREATE_CHANGES_TABLE = "CREATE TABLE IF NOT EXISTS changes(type int, vulnerability_id int, "\
                           "vulnerability_subid int, previous_id int, current_id int, time int, PRIMARY KEY(type, " \
                           "vulnerability_id, vulnerability_subid, previous_id, current_id, time))"
    SAVE_CHANGE = "INSERT INTO changes(type, vulnerability_id, vulnerability_subid, previous_id, " \
                  "current_id, time) VALUES (?, ?, ?, ?, ?, ?)"

    def __init__(self, filename="storage.sqlite3"):

        """
        Init storage

        Args:
            filename (str): filename of provided storage

        """
        self.filename = filename
        self.conn = None
        self._cursor = None
        self.log = log.getLogger('storage')
        self.cfg = cfg

    def init_schema(self):
        """
        Initialize database schema

        Returns:
            None

        """
        self.execute(self._create_tables())
        self.execute(self._clear_security_scans())

    def get_last_rowid(self):
        return self.execute((self.GET_LAST_ROWID,))[0][0] or None

    def connect(self):
        self.conn = sqlite3.connect(self.filename, check_same_thread=True)
        self._cursor = self.conn.cursor()

    def close(self):
        assert isinstance(self.conn, sqlite3.Connection)
        self.conn.close()
        self.conn = None
        self._cursor = None

    @property
    def cursor(self):
        """
        Returns:
            handler to the database cursor

        """
        return self._cursor

    def _select_where(self, table, args, operator='='):
        """
        Prepares list of AND conditions for WHERE, and list of arguments to pass for prepare statement

        Args:
            table (str):
            args (dict): dict of args. Every key is treat as column name except `operator` and `or`
            operator (str): Operator which is used for comparison

        Returns:
            list, list

        """
        arguments = []
        where = []

        if not args:
            return where, arguments

        for key, value in args.items():
            # For operator key, value is a dict of args
            if key == 'operator':
                for op, val in value.items():
                    stmt = self._select_where(table, val, op)
                    where.extend(stmt[0])
                    arguments.extend(stmt[1])
                continue

            # For or, value contains list of dicts (args)
            if key == 'or':
                _or = []
                for query in value:
                    stmt = self._select_where(table, query, operator)
                    arguments.extend(stmt[1])
                    _or.append(" ({}) ".format(" AND ".join(stmt[0])))
                where.append("({})".format(" OR ".join(_or)))
                continue

            # Every other key is treat as column name
            if key in self.TABLES[table]['columns']:
                if value is None:
                    if operator == '=':
                        where.append("{}.{} IS ?".format(table, key))
                    elif operator == '!=':
                        where.append("{}.{} IS NOT ?".format(table, key))
                    else:
                        raise AttributeError("Trying to compare NULL by '{}' with `{}`".format(operator, key))
                else:
                    where.append("{}.{} {} ?".format(table, key, operator))

                if isinstance(value, TransportProtocol):
                    arguments.append(self._protocol_to_iana(value))
                elif isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    arguments.append(str(value))
                else:
                    arguments.append(value)

            else:
                raise AttributeError("Unknown column `{}` for `{}`".format(key, table))

        return where, arguments

    def select(self, table, limit=None, page=0, where=None, join=None, **kwargs):
        """
        Builder for select function.

        Args:
            table (str): table name
            limit (int): LIMIT value
            page (int): OFFSET = page*limit
            where (dict): dict which can contains special conditions like `or` or comparisons other than `=`.
                          list of special keys:
                           - or - contains list of `where` dicts
                           - operator - operator:value dict, where value is a `where` dict and operator is SQL operator
                                        e.g. `<`, `!=`
                          all other keys are treat as column names
            join (dict): It requires 4 keys:
             - table - which table should be joined
             - from - column name from base table for join
             - to - column name from joining table
             - where - this same like `where`
            **kwargs (dict): dict of column_name: value, which is treat as list of conditions for query

        Returns:
            object base on table type

        """
        arguments = []
        _where = []
        join_stmt = ''
        limit_stmt = "LIMIT {} OFFSET {}".format(int(limit), int(limit)*int(page)) if limit else ''

        if isinstance(where, dict):
            kwargs.update(where)
        stmt = self._select_where(table, kwargs)
        _where.extend(stmt[0])
        arguments.extend(stmt[1])

        if join:
            _table = join['table']
            join_stmt = " INNER JOIN {} ON {}.{} = {}.{}".format(_table, table, join['from'], _table, join['to'])

            stmt = self._select_where(_table, join['where'])
            _where.extend(stmt[0])
            arguments.extend(stmt[1])

        where = '' if not _where else " WHERE {}".format(" AND ".join(_where))

        columns = ", ".join("{}.{}".format(table, column) for column in self.TABLES[table]['columns'])
        rows = self.execute((self.SELECT_QUERY.format(columns=columns, table=table, join=join_stmt, where=where,
                                                      order=self.TABLES[table]['order'], limit=limit_stmt),
                             tuple(arguments)))

        return [getattr(self, self.TABLES[table]['factor'])(row) for row in rows]

    def scans(self, limit=10, page=0):
        return self.select('scans', limit, page)

    def nodes_scans(self, limit=10, page=0):
        return self.select('nodes_scans', limit, page)

    def ports_scans(self, limit=10, page=0):
        return self.select('ports_scans', limit, page)

    def security_scans(self, limit=100, page=0):
        return self.select('security_scans', limit, page)

    def vulnerabilities(self, limit=10, page=0):
        return self.select('vulnerabilities', limit, page)

    def select_by_id(self, table, rowid):
        result = self.select(table, 1, 0, rowid=rowid)
        return result[0] if result else None

    def scan_by_id(self, node_scan_id):
        return self.select_by_id('scans', node_scan_id)

    def vulnerability_by_id(self, vuln_id):
        return self.select_by_id('vulnerabilities', vuln_id)

    def node_scan_by_id(self, node_scan_id):
        return self.select_by_id('nodes_scans', node_scan_id)

    def port_scan_by_id(self, port_scan_id):
        return self.select_by_id('ports_scans', port_scan_id)

    def security_scan_by_id(self, sec_scan_id):
        return self.select_by_id('security_scans', sec_scan_id)

    def _save_node(self, node, scan, scan_id=None, timestamp=None):
        """
        Saves node into to the storage

        Args:
            node (Node): node to save into storage

        Returns:
            tuple

        """
        if not scan_id:
            scan_id = self.get_scan_id(scan)

        return self.SAVE_NODE_QUERY, (scan_id, node.id, str(node.ip), timestamp or time.time())

    def _save_nodes(self, nodes, scan):
        """
        Saves nodes into local storage

        Args:
            nodes (list):
            scan (Scan):

        Returns:
            list

        """
        scan_id = self.get_scan_id(scan)
        return [self._save_node(node=node, scan=scan, scan_id=scan_id) for node in nodes]

    def _save_port(self, port, scan, scan_id=None, timestamp=None):
        """
        Query for saving port scan into database

        Args:
            port (Port): port to save into storage

        Returns:
            tuple

        """
        if not scan_id:
            scan_id = self.get_scan_id(scan)
        return self.SAVE_PORT_QUERY, (scan_id, port.node.id, str(port.node.ip), port.number,
                                      self._protocol_to_iana(port.transport_protocol), timestamp or time.time())

    def _save_ports(self, ports, scan):
        """
        Queries for saving ports scans into database

        Args:
            ports (list):

        Returns:
            list

        """
        scan_id = self.get_scan_id(scan)
        return [self._save_port(port=port, scan=scan, scan_id=scan_id) for port in ports]

    def _save_security_scan(self, exploit, port, scan):
        """
        Queries for saving scan into database

        Args:
            exploit (Exploit): needs some exploit details to save into storage
            port (Port): needs some port details to save into storage
            scan (Scan):

        Returns:
            list

        """
        log.debug("Saving scan details: scan_start(%s), scan_end(%s), exploit_id(%s), node_id(%s), node(%s), port(%s)",
                  port.scan.start, port.scan.end, exploit.id, port.node.id, str(port.node), str(port))
        queries = []
        iana = self._protocol_to_iana(port.transport_protocol)
        scan_id = self.get_scan_id(scan)

        queries.append((self.SAVE_SECURITY_SCAN_DETAIL, (scan_id, exploit.id, exploit.app, exploit.name, port.node.id,
                                                         str(port.node.ip), iana, port.number)))

        if port.scan.start:
            queries.append((self.SAVE_SECURITY_SCAN_DETAIL_START, (port.scan.start, exploit.id, exploit.app,
                                                                   exploit.name, port.node.id, str(port.node.ip), iana,
                                                                   iana, port.number, scan_id)))

        if port.scan.end:
            queries.append((self.SAVE_SECURITY_SCAN_DETAIL_END, (port.scan.end, exploit.id, exploit.app, exploit.name,
                                                                 port.node.id, str(port.node.ip), iana, iana,
                                                                 port.number, scan_id)))
        return queries

    def _save_security_scans(self, exploits, port, scan):
        """
        Queries for saving scans into database

        Args:
            exploits (list): List of Exploits
            port (Port):

        Returns:
            list
 .

        """
        return [query for exploit in exploits for query in self._save_security_scan(exploit=exploit, port=port,
                                                                                    scan=scan)]

    def _save_change(self, change):
        """
        Query for saving changes between scans

        Args:
            change: VulnerabilityChange

        Returns:
            tuple

        """
        return self.SAVE_CHANGE, (change.type.value, change.vulnerability_id, change.vulnerability_subid,
                                  change.previous_finding.rowid if change.previous_finding else None,
                                  change.current_finding.rowid if change.current_finding else None, change.time)

    def _save_changes(self, changes):
        """
        Queries for saving multiple changes into database

        Args:
            changes (list):

        Returns:
            list

        """
        return [self._save_change(change) for change in changes]

    def _clear_security_scans(self):
        """
        Query for cleaning table

        Returns:
            tuple

        """
        log.debug('Cleaning scan details')
        return self.CLEAR_SECURITY_SCANS,

    def _create_tables(self):
        """
        List of queries for table creation

        Returns:
            list

        """
        queries = [(self.CREATE_SCANS_TABLE,),
                   (self.CREATE_SECURITY_SCANS_TABLE,),
                   (self.CREATE_PORTS_TABLE,),
                   (self.CREATE_NODES_TABLE,),
                   (self.CREATE_VULNERABILITIES_TABLE,),
                   (self.CREATE_CHANGES_TABLE,)]

        return queries

    def execute(self, query):
        """
        Execute query or queries.

        Args:
            query (list|tuple|str):

        Returns:
            None|list

        """
        log_id = uuid.uuid4()
        log.debug("Executing query with id: %s", log_id)

        try:
            if isinstance(query, list):
                self.log.debug("[%s] executing %i queries", log_id, len(query))
                for row in query:
                    self.cursor.execute(*row)
            else:
                self.log.debug("[%s] executing query: %s", log_id, query)
                return self.cursor.execute(*query).fetchall()
        except sqlite3.Error as exception:
            self.log.exception("[%s] exception occured:", log_id)
            raise exception

        self.conn.commit()

    def save_node(self, node, scan):
        """
        Save node to database

        Args:
            node (Node):
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_node(node=node, scan=scan))

    def save_nodes(self, nodes, scan):
        """
        Save nodes to database

        Args:
            nodes (list[Node]):
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_nodes(nodes=nodes, scan=scan))

    def get_nodes(self, scan, pasttime=0, timestamp=None):
        """
        Get nodes from database since timestamp. If timestamp is not given, it's computed basing on pastime.

        Args:
            pasttime (int):
            timestamp (int):
            scan (Scan):

        Returns:
            list[Node]

        """
        if timestamp is None:
            timestamp = time.time() - pasttime

        return [node_scan.node for node_scan in self.select(
            'nodes_scans', where={'operator': {'>': {'time': timestamp}}},
            join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where': {
                'protocol': scan.protocol, 'scanner_name': scan.scanner}})]

    def get_vulnerabilities(self, port, exploit, scan):
        """
        Get vulnerabilities for given port, exploit and scan

        Args:
            port (Port):
            exploit (Exploit):
            scan (Scan):

        Returns:
            list[Node]

        """
        return self.select(table='vulnerabilities', node_id=port.node.id, node_ip=port.node.ip, port=port.number,
                           port_protocol=port.transport_protocol, vulnerability_id=exploit.id, scan_id=scan.rowid)

    def save_port(self, port, scan):
        """
        Save port to database

        Args:
            port (Port):

        Returns:
            None

        """
        return self.execute(self._save_port(port=port, scan=scan))

    def save_ports(self, ports, scan):
        """
        Save ports to database

        Args:
            ports (list):

        Returns:
            None

        """
        return self.execute(self._save_ports(ports=ports, scan=scan))

    def get_ports(self, scan, pasttime=900):
        """
        Get ports from database from pasttime.

        Args:
            scan (Scan):
            pasttime (int):

        Returns:
            list[Port]

        """
        timestamp = time.time() - pasttime
        return [port_scan.port for port_scan in self.select(
            'ports_scans', where={'operator': {'>': {'time': timestamp}}},
            join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where': {
                'protocol': scan.protocol,
                'scanner_name': scan.scanner
            }}
        )]

    def get_ports_by_scan_and_node(self, node, scan):
        """
        Get ports from database for given node and scan.

        Args:
            node (Node):
            scan (Scan):

        Returns:
            list[Port]

        """
        return self.select("ports_scans", node_id=node.id, node_ip=node.ip, scan_id=scan.rowid)

    def get_nodes_by_scan(self, scan):
        """
        Get nodes from database for given scan.

        Args:
            scan (Scan):

        Returns:
            list[Port]

        """
        nodes = [el.node for el in self.select("nodes_scans", scan_id=scan.rowid)]

        for node in nodes:
            node.scan = scan

        return nodes

    def save_security_scan(self, exploit, port, scan):
        """
        Save scan of port by exploit to database

        Args:
            exploit (Exploit):
            port (Port):
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_security_scan(exploit=exploit, port=port, scan=scan))

    def save_security_scans(self, exploits, port, scan):
        """
        Save scans of port to database basing on given exploits

        Args:
            exploits (list):
            port (Port):
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_security_scans(exploits=exploits, port=port, scan=scan))

    def get_security_scan_info(self, port, app, scan):
        """
        Get security scan info from database

        Args:
            port (Port):
            app (str):
            scan (Scan):

        Returns:
            tuple

        """
        return self.select("security_scans", exploit_app=app, node_id=port.node.id, node_ip=port.node.ip,
                           port_protocol=port.transport_protocol, port_number=port.number,
                           join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where':
                               {'protocol': scan.protocol, 'scanner_name': scan.scanner}})

    def save_changes(self, changes):
        """
        Save changes to database

        Args:
            changes (list):

        Returns:
            None

        """
        return self.execute(self._save_changes(changes=changes))

    def clear_security_scans(self):
        """
        Clear broken scan details

        Returns:
            None

        """
        return self.execute(self._clear_security_scans())

    def create_tables(self):
        """
        Create tables in storage

        Returns:
            None

        """
        return self.execute(self._create_tables())

    def get_ports_by_nodes(self, nodes, pasttime=0, timestamp=None, protocol=None, portdetection_only=False):
        """
        Returns list of port for given list of nodes. protocol and portdetection_only has special meanings
        (in this order):
             - If portdetection_only is True, then function returns ports only from portdetection scans
             - If protocol is None then returns ports belonging to any protocol
             - If protocol is not None then returns ports only fot this protocol

        ToDo: Split on three different functions and validate usability of code paths

        Args:
            nodes (list[Node]):
            pasttime (int):
            timestamp (int):
            protocol (TransportProtocol|None):
            portdetection_only (bool):

        Returns:

        """
        if not nodes:
            return []

        if timestamp is None:
            timestamp = time.time() - pasttime

        ports_scans = []

        if portdetection_only is True:
            for where in self._gen_where_for_ports_by_nodes(nodes=nodes, timestamp=timestamp):
                ports_scans.extend(self.select(
                    table='ports_scans',
                    where=where,
                    join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where': {
                        'or': [
                            {'scanner_name': TCPScanner.NAME},
                            {'scanner_name': UDPScanner.NAME}
                        ]}}))

        elif protocol is None:
            for where in self._gen_where_for_ports_by_nodes(nodes=nodes, timestamp=timestamp):
                ports_scans.extend(self.select(
                    table='ports_scans',
                    where=where
                ))

        else:
            for where in self._gen_where_for_ports_by_nodes(nodes=nodes, timestamp=timestamp):
                ports_scans.extend(self.select(
                    table='ports_scans',
                    port_protocol=protocol,
                    where=where
                ))

        return_value = []

        for port_scan in ports_scans:
            node = nodes[nodes.index(port_scan.node)]
            port_scan.port.scan = Scan(start=node.scan.start)
            return_value.append(port_scan.port)

        return return_value

    def _gen_where_for_ports_by_nodes(self, nodes, timestamp):
        nodes_limit = cfg['storage.max_nodes_query']
        for i in range(ceil(len(nodes) / nodes_limit)):
            yield {'or': [{'node_ip': node.ip, 'node_id': node.id} for node in nodes[i*nodes_limit:(i+1)*nodes_limit]],
                   'operator': {'>': {'time': timestamp}}}

    def _transport_protocol(self, number):
        """
        Convert database protocol to TransportProtocol

        Args:
            number (int|None):

        Returns:
            TransportProtocol|None - None if number is None

        """
        if number is None:
            return None

        return TransportProtocol.from_iana(number)

    def _protocol_to_iana(self, protocol):
        """
        Convert database protocol to TransportProtocol

        Args:
            protocol (TransportProtocol):

        Returns:
            int|None - None if number is None

        """
        if protocol is None:
            return None

        return protocol.iana

    def _save_scan(self, scan):
        """
        Queries for saving scan into database

        Args:
            scan (Scan):

        Returns:
            list

        """
        return self.SAVE_SCAN_QUERY, (self._protocol_to_iana(scan.protocol), scan.scanner, scan.start, scan.end)

    def _update_scan(self, scan):
        return self.UPDATE_SCAN_END_QUERY, (scan.end, scan.rowid)

    def save_scan(self, scan):
        """
        Save scan into storage

        Args:
            scan (Scan):

        Returns:

        """
        self.execute(self._save_scan(scan=scan))
        scan.rowid = self.get_last_rowid()
        return scan

    def update_scan(self, scan):
        """
        Update scan in storage

        Args:
            scan (Scan):

        Returns:

        """
        return self.execute(self._update_scan(scan=scan))

    def get_scan_id(self, scan):
        """
        Get scan_id

        Args:
            scan (Scan):

        Returns:
            int

        """
        if scan.rowid:
            return scan.rowid

        _scan = self.select("scans", limit=1, protocol=scan.protocol, scanner_name=scan.scanner, scan_start=scan.start)
        return _scan[0].rowid if _scan else None

    def get_scans(self, protocol, scanner_name, amount=2):
        """
        Obtain scans from storage. Scans are taken from newest to oldest

        Args:
            protocol (TransportProtocol):
            scanner_name (str):
            amount (int):

        Returns:
            list[Scan]

        """
        return self.select("scans", protocol=protocol, limit=amount, scanner_name=scanner_name)

    def get_scans_by_node(self, node, scan):
        """
        Obtain scans from storage based on given node and scan

        Args:
            node (Node):
            scan (Scan):

        Returns:
            list[Scan]

        """
        return self.select("scans", limit=2, protocol=scan.protocol, scanner_name=scan.scanner, join={
            'table': 'nodes_scans',
            'from': 'rowid',
            'to': 'scan_id',
            'where': {'node_id': node.id, 'node_ip': node.ip}
        })

    def get_scans_by_security_scan(self, exploit, port):
        """
        Obtain scans from storage based on given exploit and port

        Args:
            exploit (Exploit):
            port (Port):

        Returns:
            list[Scan]

        """
        return self.select(table='scans', join={'table': 'security_scans', 'from': 'rowid', 'to': 'scan_id', 'where':{
            'node_id': port.node.id, 'node_ip': port.node.ip, 'port_number': port.number,
            'port_protocol': port.transport_protocol, 'exploit_id': exploit.id, 'exploit_app': exploit.app,
            'exploit_name': exploit.name
        }})

    def get_scan_by_id(self, scan_id):
        """
        Obtain scan from storage

        Args:
            scan_id (int):

        Returns:
            Scan

        """
        return self.scan_by_id(scan_id)

    def _save_vulnerabilities(self, vulnerabilities, scan):
        """
        Save vulnerabilities into local storage

        Args:
            vulnerabilities (list[Vulnerability]): list of Vulnerability
            scan (Scan):

        Returns:
            None

        """
        scan_id = self.get_scan_id(scan)
        queries = [(self.SAVE_VULNERABILITY, (scan_id, vuln.port.node.id, str(vuln.port.node.ip),
                                              self._protocol_to_iana(vuln.port.transport_protocol), vuln.port.number,
                                              vuln.exploit.id, vuln.subid, vuln.cve, vuln.cvss, vuln.output,
                                              vuln.time))
                   for vuln in vulnerabilities]
        return queries

    def save_vulnerabilities(self, vulnerabilities, scan):
        """
        Save vulnerabilities into local storage

        Args:
            vulnerabilities (list[Vulnerability]): list of Vulnerability
            scan (Scan):

        Returns:
            None

        """
        return self.execute(self._save_vulnerabilities(vulnerabilities=vulnerabilities, scan=scan))

    def _scan_from_row(self, row):
        return Scan(start=row[3], end=row[4], protocol=self._transport_protocol(row[1]), scanner=row[2], rowid=row[0])

    def _nodes_scan_from_row(self, row):
        return NodeScan(node=Node(node_id=row[1], ip=ipaddress.ip_address(row[2])), rowid=row[0], timestamp=row[4],
                        scan=self.get_scan_by_id(row[3]))

    def _port_scan_from_row(self, row):
        return PortScan(port=Port(node=Node(node_id=row[1], ip=ipaddress.ip_address(row[2])),
                                  number=row[4], transport_protocol=TransportProtocol.from_iana(row[5])),
                        rowid=row[0],
                        timestamp=row[6],
                        scan=self.get_scan_by_id(row[3]))

    def _vulnerability_from_row(self, row):
        return Vulnerability(port=Port(transport_protocol=self._transport_protocol(row[4]), number=row[5],
                                       node=Node(node_id=row[2], ip=ipaddress.ip_address(row[3]))),
                             exploit=Exploit(exploit_id=row[6]), subid=row[7], cve=row[8], cvss=row[9], output=row[10],
                             vuln_time=row[11], rowid=row[0], scan=self.get_scan_by_id(row[1]))

    def _sec_scan_from_row(self, row):
        return SecurityScan(port=Port(node=Node(node_id=row[5], ip=ipaddress.ip_address(row[6])),
                                      transport_protocol=self._transport_protocol(row[7]), number=row[8]),
                            rowid=row[0], scan=self.get_scan_by_id(row[1]), scan_start=row[9], scan_end=row[10],
                            exploit=Exploit(exploit_id=row[2], app=row[3], name=row[4]))

    def scans_by_node_scan(self, node_scan):
        """
        Return list of scans related to given NodeScan

        Args:
            node_scan (NodeScan):

        Returns:
            list[Scan]

        """
        return self.select('scans', 30, 0, join={'from': 'rowid', 'to': 'scan_id', 'table': 'nodes_scans', 'where': {
            'node_id': node_scan.node.id,
            'node_ip': str(node_scan.node.ip),
        }})

    def scans_by_port_scan(self, port_scan):
        """
        Return list of scans related to given PortScan

        Args:
            port_scan (PortScan):

        Returns:
            list[Scan]

        """
        return self.select('scans', 30, 0, join={'from': 'rowid', 'to': 'scan_id', 'table': 'ports_scans', 'where': {
            'node_id': port_scan.node.id,
            'node_ip': port_scan.node.ip,
            'port': port_scan.port.number,
            'port_protocol': port_scan.port.transport_protocol
        }})

    def nodes_scans_by_scan(self, scan):
        """
        Return list of NodeScan for given Scan

        Args:
            scan (Scan):

        Returns:
            list[NodeScan]

        """
        return self.select("nodes_scans", scan_id=scan.rowid)

    def ports_scans_by_scan(self, scan):
        """
        Return list of PortScan for given Scan

        Args:
            scan (Scan):

        Returns:
            list[PortScan]

        """
        return self.select("ports_scans", scan_id=scan.rowid)

    def save_node_scan(self, node_scan):
        """
        Save NodeScan to the storage. Returns NodeScan with updated ROWID

        Args:
            node_scan (NodeScan):

        Returns:
            NodeScan

        """
        self.execute(self._save_node(node_scan.node, node_scan.scan, timestamp=node_scan.timestamp))
        node_scan.rowid = self.get_last_rowid()
        return node_scan

    def save_port_scan(self, port_scan):
        """
        Save PortScan to the storage. Returns PortScan with updated ROWID

        Args:
            port_scan (PortScan):

        Returns:
            PortScan

        """
        self.execute(self._save_port(port_scan.port, port_scan.scan, timestamp=port_scan.timestamp))

    def save_sec_scan(self, sec_scan):
        """
        Save SecurityScan to the storage. Returns SecurityScan with updated rowid

        Args:
            sec_scan (SecurityScan):

        Returns:
            SecurityScan

        """
        self.execute((self.SAVE_SECURITY_SCAN, (sec_scan.scan.rowid, sec_scan.exploit.id, sec_scan.exploit.app,
                                                sec_scan.exploit.name, sec_scan.node.id, str(sec_scan.node.ip),
                                                self._protocol_to_iana(sec_scan.port.transport_protocol),
                                                sec_scan.port.number, sec_scan.scan_start, sec_scan.scan_end)))

        sec_scan.rowid = self.get_last_rowid()

    def scans_by_security_scan(self, sec_scan):
        """
        Returns scans for given SecurityScan

        Args:
            sec_scan (SecurityScan):

        Returns:
            list [Scan]

        """
        return self.select('scans', 30, 0,
                           join={'from': 'rowid', 'to': 'scan_id', 'table': 'security_scans', 'where': {
                                    'node_id': sec_scan.node.id,
                                    'node_ip': sec_scan.node.ip,
                                    'port_number': sec_scan.port.number,
                                    'port_protocol': sec_scan.port.transport_protocol,
                                    'exploit_id': sec_scan.exploit.id,
                                    'exploit_app': sec_scan.exploit.app,
                                    'exploit_name': sec_scan.exploit.name,
                                }})

    def scans_by_vulnerability(self, vuln):
        """
        Returns scans for given vulnerability

        Args:
            vuln (Vulnerability):

        Returns:
            list [Scan]

        """
        return self.select('scans', 30, 0,
                           join={'from': 'rowid', 'to': 'scan_id', 'table': 'vulnerabilities', 'where': {
                                    'node_id': vuln.port.node.id,
                                    'node_ip': vuln.port.node.ip,
                                    'port': vuln.port.number,
                                    'port_protocol': vuln.port.transport_protocol,
                                    'vulnerability_id': vuln.exploit.id,
                                    'vulnerability_subid': vuln.subid,
                                }})

    def save_vulnerability(self, vuln):
        """
        Save vulnerability into storage

        Args:
            vuln (Vulnerability):

        Returns:
            None

        """
        self.execute((self.SAVE_VULNERABILITY, (vuln.scan.rowid, vuln.port.node.id, str(vuln.port.node.ip),
                                                self._protocol_to_iana(vuln.port.transport_protocol), vuln.port.number,
                                                vuln.exploit.id, vuln.subid, vuln.cve, vuln.cvss, vuln.output,
                                                vuln.time)))
