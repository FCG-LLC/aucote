"""
Storage
=======

Storage is internal database which helps with processing scans. Data from storage are mostly available via API

Currently storage consists of 5 tables

scans
-----

+-------+----------+--------------+------------+----------+
| rowid | protocol | scanner_name | scan_start | scan_end |
+=======+==========+==============+============+==========+
+-------+----------+--------------+------------+----------+

columns:
 - rowid (int) - row identifier
 - protocol (int) - protocol which was scanned
 - scanner_name (string) - name of scanner
 - scan_start (int) - scan start timestamp
 - scan_end (int) - scan end timestamp

nodes_scans
-----------

+--------+---------+---------+---------+------+
| rowid  | node_id | node_ip | scan_id | time |
+========+=========+=========+=========+======+
+--------+---------+---------+---------+------+

columns:
 - rowid (int) - row identifier
 - node_id (int) - node identifier (topdis base)
 - node_ip (string) - node ip address
 - scan_id (int) - scan identifier (scans.rowid)
 - time (int) - node detecting time

ports_scans
-----------

+-------+---------+---------+---------+------+---------------+------+
| rowid | node_id | node_ip | scan_id | port | port_protocol | time |
+=======+=========+=========+=========+======+===============+======+
+-------+---------+---------+---------+------+---------------+------+

columns:
 - rowid (int) - row identifier
 - node_id (int) - node identifier (topdis base)
 - node_ip (string) - node ip address
 - scan_id (int) - scan identifier (scans.rowid)
 - port (int) - port number
 - port_protocol (int) - port protocol
 - time (int) - port detecting time

security_scans
--------------

+-------+---------+------------+-------------+--------------+---------+---------+---------------+-------------+----------------+--------------+
| rowid | scan_id | exploit_id | exploit_app | exploit_name | node_id | node_ip | port_protocol | port_number | sec_scan_start | sec_scan_end |
+=======+=========+============+=============+==============+=========+=========+===============+=============+================+==============+
+-------+---------+------------+-------------+--------------+---------+---------+---------------+-------------+----------------+--------------+

columns:
 - rowid (int) - row identifier
 - scan_id (int) - scan identifier (scans.rowid)
 - exploit_id (int) - script identifier
 - exploit_app (int) - script app name
 - exploit_name (int) - script name
 - node_id (int) - node identifier (topdis base)
 - node_ip (string) - node ip address
 - port_protocol (int) - port protocol
 - port_number (int) - port number
 - sec_scan_start (int) - security scan start timestamp
 - sec_scan_end (int) security scan end timestamp

vulnerabilities
---------------

+-------+---------+---------+---------+---------------+------+------------------+---------------------+-----+------+---------------+-----------------+
| rowid | scan_id | node_id | node_ip | port_protocol | port | vulnerability_id | vulnerability_subid | cve | cvss | output | time | expiration_time |
+=======+=========+=========+=========+===============+======+==================+=====================+=====+======+===============+=================+
+-------+---------+---------+---------+---------------+------+------------------+---------------------+-----+------+---------------+-----------------+

columns:
 - rowid (int) - row identifier
 - scan_id (int) - scan identifier (scans.rowid)
 - node_id (int) - node identifier (topdis base)
 - node_ip (string) - node ip address
 - port_protocol (int) - port protocol
 - port (int) - port number
 - vulnerability_id (int) - script identifier
 - vulnerability_subid (int) - vulnerability subidentifier (allows to store multiple vulnerabilites by one script)
 - cve (string) - CVE identifier
 - cvss (string) - CVSS value (0 to 10 with 0.1 resolution)
 - output (string) - vulnerability details
 - time (int) - vulnerability detection time
 - expiration_time (int) - vulnerability expiration time

"""
import ipaddress
import os
import sqlite3
import time
import logging as log
import uuid

from math import ceil

import threading

import psycopg2

from fixtures.exploits import Exploit
from structs import Port, Node, TransportProtocol, Scan, Vulnerability, PortScan, SecurityScan, NodeScan
from utils.database_interface import DbInterface
from scans.tcp_scanner import TCPScanner
from scans.udp_scanner import UDPScanner


class Storage(DbInterface):
    """
    This class provides local storage functionality

    """

    DRIVER_POSTGRES = 'postgres'
    DRIVER_SQLITE3 = 'sqlite3'

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
                        'vulnerability_subid', 'cve', 'cvss', 'output', 'time', 'expiration_time'],
            'factor': '_vulnerability_from_row',
            'order': 'ORDER BY time DESC'
        },
    }

    QUERY_SELECT = "SELECT {columns} FROM {table} {join} {where} {order} {limit}"

    QUERY_GET_LAST_ROWID = "SELECT LASTVAL()"

    QUERY_CREATE_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS scans(rowid SERIAL UNIQUE, protocol int, " \
                               "scanner_name VARCHAR, scan_start int, scan_end int, UNIQUE (protocol, scanner_name, " \
                               "scan_start))"
    QUERY_SAVE_SCAN = "INSERT INTO scans (protocol, scanner_name, scan_start, scan_end) VALUES (%s, %s, %s, %s)"
    QUERY_UPDATE_SCAN_END = "UPDATE scans set scan_end = %s WHERE ROWID=%s"

    QUERY_CREATE_NODES_TABLE = "CREATE TABLE IF NOT EXISTS nodes_scans(rowid SERIAL UNIQUE, scan_id int, " \
                               "node_id BIGINT, node_ip text, time int, primary key (scan_id, node_id, node_ip))"
    QUERY_SAVE_NODE = "INSERT INTO nodes_scans (scan_id, node_id, node_ip, time) VALUES (%s, %s, %s, %s)"

    QUERY_CREATE_PORTS_TABLE = "CREATE TABLE IF NOT EXISTS ports_scans (rowid SERIAL UNIQUE, scan_id int, " \
                               "node_id BIGINT, node_ip text, port int, port_protocol int, time int, " \
                               "primary key (scan_id, node_id, node_ip, port, port_protocol))"
    QUERY_SAVE_PORT = "INSERT INTO ports_scans (scan_id, node_id, node_ip, port, port_protocol, time) " \
                      "VALUES (%s, %s, %s, %s, %s, %s)"

    QUERY_CREATE_SECURITY_SCANS_TABLE = "CREATE TABLE IF NOT EXISTS security_scans (rowid SERIAL UNIQUE, " \
                                        "scan_id int, exploit_id int, exploit_app text, exploit_name text, " \
                                        "node_id BIGINT, node_ip text, port_protocol int, port_number int, " \
                                        "sec_scan_start float, sec_scan_end float,"\
                                        " PRIMARY KEY (scan_id, exploit_id, node_id, node_ip, port_protocol, " \
                                        "port_number))"
    QUERY_SAVE_SECURITY_SCAN_DETAIL = "INSERT INTO security_scans (scan_id, exploit_id, exploit_app," \
                                      " exploit_name, node_id, node_ip, port_protocol, port_number) VALUES " \
                                      "(%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (scan_id, exploit_id, node_id, " \
                                      "node_ip, port_protocol, port_number) DO NOTHING"
    QUERY_SAVE_SECURITY_SCAN_DETAIL_START = "UPDATE security_scans SET sec_scan_start=%s WHERE exploit_id=%s AND " \
                                            "exploit_app=%s AND exploit_name=%s AND node_id=%s AND node_ip=%s AND " \
                                            "(port_protocol=%s OR (%s IS NULL AND port_protocol IS NULL)) " \
                                            "AND port_number=%s AND scan_id=%s"
    QUERY_SAVE_SECURITY_SCAN_DETAIL_END = "UPDATE security_scans SET sec_scan_end=%s WHERE exploit_id=%s AND " \
                                          "exploit_app=%s AND exploit_name=%s AND node_id=%s AND node_ip=%s " \
                                          "AND (port_protocol=%s OR (%s IS NULL AND port_protocol IS NULL)) " \
                                          "AND port_number=%s AND scan_id=%s"
    QUERY_CLEAR_SECURITY_SCANS = "DELETE FROM security_scans WHERE sec_scan_start >= sec_scan_end OR sec_scan_start " \
                                 "IS NULL OR sec_scan_end IS NULL"

    QUERY_SAVE_SECURITY_SCAN = "INSERT INTO security_scans (scan_id, exploit_id, exploit_app, exploit_name," \
                               " node_id, node_ip, port_protocol, port_number, sec_scan_start, sec_scan_end) " \
                               "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

    QUERY_CREATE_VULNERABILITIES_TABLE = "CREATE TABLE IF NOT EXISTS vulnerabilities(rowid SERIAL UNIQUE, " \
                                         "scan_id int, node_id BIGINT, " \
                                         "node_ip text, port_protocol int, port int, vulnerability_id int, " \
                                         "vulnerability_subid int, cve text, cvss text, output text, time int, " \
                                         "expiration_time int, primary key(scan_id, node_id, " \
                                         "node_ip, port_protocol, port, vulnerability_id, vulnerability_subid))"
    QUERY_SAVE_VULNERABILITY = "INSERT INTO vulnerabilities (scan_id, node_id, node_ip, port_protocol, port, " \
                               "vulnerability_id, vulnerability_subid, cve, cvss, output, time) " \
                               "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

    QUERY_UPDATE_VULNERABILITY_EXPIRATION = "UPDATE vulnerabilities SET expiration_time=%s WHERE scan_id=%s AND " \
                                            "node_id=%s AND node_ip=%s AND port_protocol=%s AND port=%s AND " \
                                            "vulnerability_id=%s AND vulnerability_subid=%s"

    QUERY_CREATE_CHANGES_TABLE = "CREATE TABLE IF NOT EXISTS changes(rowid SERIAL UNIQUE, type int, " \
                                 "vulnerability_id int, vulnerability_subid int, previous_id int, current_id int, " \
                                 "time int, PRIMARY KEY(type, vulnerability_id, vulnerability_subid, previous_id, " \
                                 "current_id, time))"
    QUERY_SAVE_CHANGE = "INSERT INTO changes(type, vulnerability_id, vulnerability_subid, previous_id, " \
                        "current_id, time) VALUES (%s, %s, %s, %s, %s, %s)"

    def __init__(self, conn_string: str = "storage.sqlite3", nodes_limit: int = 200):

        """
        Init storage
        """
        self._conn_string = conn_string
        self.conn = None
        self._cursor = None
        self.log = log.getLogger('storage')
        self.nodes_limit = nodes_limit
        self._thread = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def is_correct_thread(self):
        return not self._thread or self._thread and threading.get_ident() == self._thread.ident

    def set_thread(self, thread):
        self._thread = thread

    def init_schema(self):
        """
        Initialize database schema
        """
        log.debug('Initializing database schema')
        self.execute(self._create_tables())
        self.execute(self._clear_security_scans())

    def _get_last_rowid(self):
        return (self.QUERY_GET_LAST_ROWID,)

    def connect(self):
        if not self.is_correct_thread:
            raise Exception("Connection from incorrect thread")

        log.debug("Connecting to database")
        try:
            self.conn = psycopg2.connect(self._conn_string)
        except Exception:
            log.exception('Exception during connecting to database')
            os._exit()
            raise Exception
        log.debug("Connected to database")
        self._cursor = self.conn.cursor()
        self._cursor = self.conn.cursor()

    def close(self):
        if self.conn is not None:
            self.conn.close()
        self.conn = None
        self._cursor = None

    @property
    def cursor(self):
        """
        Returns handler to the database cursor
        """
        return self._cursor

    def _select_where(self, table: str, args: dict, operator: str = '=') -> (list, list):
        """
        Prepares list of AND conditions for WHERE, and list of arguments to pass for prepare statement

        table
        args - dict of args. Every key is treat as column name except `operator` and `or`
        operator - Operator which is used for comparison
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
                        where.append("{}.{} IS %s".format(table, key))
                    elif operator == '!=':
                        where.append("{}.{} IS NOT %s".format(table, key))
                    else:
                        raise AttributeError("Trying to compare NULL by '{}' with `{}`".format(operator, key))
                else:
                    where.append("{}.{} {} %s".format(table, key, operator))

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

        * table (str): table name
        * limit (int): LIMIT value
        * page (int): OFFSET = page*limit
        * where (dict): dict which can contains special conditions like `or` or comparisons other than `=`.

        list of special keys:

            * or - contains list of `where` dicts
            * operator - operator:value dict, where value is a `where` dict and operator is SQL operator e.g. `<`, `!=`
            * all other keys are treat as column names

        * join (dict): It requires 4 keys:

            * table - which table should be joined
            * from - column name from base table for join
            * to - column name from joining table
            * where - this same like `where`

        * ** kwargs (dict): dict of column_name: value, which is treat as list of conditions for query

        Returns object base on table type
        """
        arguments = []
        _where = []
        join_stmt = ''
        limit_stmt = "LIMIT {} OFFSET {}".format(int(limit), int(limit) * int(page)) if limit else ''

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
        rows = self.execute((self.QUERY_SELECT.format(columns=columns, table=table, join=join_stmt, where=where,
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

    def _save_node(self, node: 'Node', scan: 'Scan', scan_id: int = None, timestamp: float = None) -> tuple:
        """
        Saves node into to the storage
        """
        if not scan_id:
            scan_id = self.get_scan_id(scan)

        return self.QUERY_SAVE_NODE, (scan_id, node.id, str(node.ip), timestamp or time.time())

    def _save_nodes(self, nodes: list, scan: 'Scan') -> list:
        """
        Saves nodes into local storage
        """
        scan_id = self.get_scan_id(scan)
        return [self._save_node(node=node, scan=scan, scan_id=scan_id) for node in nodes]

    def _save_port(self, port: 'Port', scan: 'Scan', scan_id: int = None, timestamp: float = None) -> tuple:
        """
        Query for saving port scan into database
        """
        if not scan_id:
            scan_id = self.get_scan_id(scan)
        return self.QUERY_SAVE_PORT, (scan_id, port.node.id, str(port.node.ip), port.number,
                                      self._protocol_to_iana(port.transport_protocol), timestamp or time.time())

    def _save_ports(self, ports: list, scan: 'Scan') -> list:
        """
        Queries for saving ports scans into database

        """
        scan_id = self.get_scan_id(scan)
        return [self._save_port(port=port, scan=scan, scan_id=scan_id) for port in ports]

    def _save_security_scan(self, exploit: 'Exploit', port: 'Port', scan: 'Scan') -> list:
        """
        Queries for saving scan into database

        Args:
        * exploit - needs some exploit details to save into storage
        * port - needs some port details to save into storage

        """
        log.debug("Saving scan details: scan_start(%s), scan_end(%s), exploit_id(%s), node_id(%s), node(%s), port(%s)",
                  port.scan.start, port.scan.end, exploit.id, port.node.id, str(port.node), str(port))
        queries = []
        iana = self._protocol_to_iana(port.transport_protocol)
        scan_id = self.get_scan_id(scan)

        queries.append(
            (self.QUERY_SAVE_SECURITY_SCAN_DETAIL, (scan_id, exploit.id, exploit.app, exploit.name, port.node.id,
                                                    str(port.node.ip), iana, port.number)))

        if port.scan.start:
            queries.append((self.QUERY_SAVE_SECURITY_SCAN_DETAIL_START, (port.scan.start, exploit.id, exploit.app,
                                                                         exploit.name, port.node.id, str(port.node.ip),
                                                                         iana,
                                                                         iana, port.number, scan_id)))

        if port.scan.end:
            queries.append(
                (self.QUERY_SAVE_SECURITY_SCAN_DETAIL_END, (port.scan.end, exploit.id, exploit.app, exploit.name,
                                                            port.node.id, str(port.node.ip), iana, iana,
                                                            port.number, scan_id)))
        return queries

    def _save_security_scans(self, exploits: list, port: 'Port', scan: 'Scan') -> list:
        """
        Queries for saving scans into database

        """
        return [query for exploit in exploits for query in self._save_security_scan(exploit=exploit, port=port,
                                                                                    scan=scan)]

    def _save_change(self, change: 'VulnerabilityChange') -> tuple:
        """
        Query for saving changes between scans

        """
        return self.QUERY_SAVE_CHANGE, (change.type.value, change.vulnerability_id, change.vulnerability_subid,
                                        change.previous_finding.rowid if change.previous_finding else None,
                                        change.current_finding.rowid if change.current_finding else None, change.time)

    def _save_changes(self, changes: list) -> list:
        """
        Queries for saving multiple changes into database

        """
        return [self._save_change(change) for change in changes]

    def _clear_security_scans(self) -> tuple:
        """
        Query for cleaning table

        """
        log.debug('Cleaning scan details')
        return self.QUERY_CLEAR_SECURITY_SCANS,

    def _create_tables(self) -> list:
        """
        List of queries for table creation

        """
        queries = [(self.QUERY_CREATE_SCANS_TABLE,),
                   (self.QUERY_CREATE_SECURITY_SCANS_TABLE,),
                   (self.QUERY_CREATE_PORTS_TABLE,),
                   (self.QUERY_CREATE_NODES_TABLE,),
                   (self.QUERY_CREATE_VULNERABILITIES_TABLE,),
                   (self.QUERY_CREATE_CHANGES_TABLE,)]

        return queries

    def execute(self, query: [list, tuple, str]) -> list:
        """
        Execute query or queries.

        """
        if not self.is_correct_thread:
            return self._thread.execute(query)
        else:
            log_id = uuid.uuid4()
            try:
                if isinstance(query, list):
                    self.log.debug("[%s] executing %i queries", log_id, len(query))
                    return [self._fetchall(row) for row in query]
                else:
                    self.log.debug("[%s] executing query: %s", log_id, query)
                    return self._fetchall(query)
            except sqlite3.Error as exception:
                self.log.error("[%s] During execution of %s", log_id, query)
                self.log.exception("[%s] exception occured:", log_id)
                raise exception

    def _fetchall(self, query):
        try:
            self.cursor.execute(*query)
        except psycopg2.DataError:
            pass

        self.conn.commit()
        if self.cursor.rowcount <= 0:
            return []

        try:
            return self.cursor.fetchall()
        except psycopg2.ProgrammingError:
            return []

    def save_nodes(self, nodes: list, scan: 'Scan'):
        """
        Save nodes to database

        """
        return self.execute(self._save_nodes(nodes=nodes, scan=scan))

    def get_nodes(self, scan: 'Scan', pasttime: float = 0, timestamp: float = None) -> list:
        """
        Get nodes from database since timestamp. If timestamp is not given, it's computed basing on pastime.

        """
        if timestamp is None:
            timestamp = time.time() - pasttime

        return [node_scan.node for node_scan in self.select(
            'nodes_scans', where={'operator': {'>': {'time': timestamp}}},
            join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where': {
                'protocol': scan.protocol, 'scanner_name': scan.scanner}})]

    def get_vulnerabilities(self, port: 'Port', exploit: 'Exploit', scan: 'Scan') -> list:
        """
        Get vulnerabilities for given port, exploit and scan

        """
        return self.select(table='vulnerabilities', node_id=port.node.id, node_ip=port.node.ip, port=port.number,
                           port_protocol=port.transport_protocol, vulnerability_id=exploit.id, scan_id=scan.rowid)

    def save_port(self, port: 'Port', scan: 'Scan'):
        """
        Save port to database

        """
        return self.execute(self._save_port(port=port, scan=scan))

    def save_ports(self, ports: list, scan: 'Scan'):
        """
        Save ports to database

        """
        return self.execute(self._save_ports(ports=ports, scan=scan))

    def get_ports(self, scan: 'Scan', pasttime: float = 900) -> list:
        """
        Get ports from database from pasttime.

        """
        timestamp = time.time() - pasttime
        return [port_scan.port for port_scan in self.select(
            'ports_scans', where={'operator': {'>': {'time': timestamp}}},
            join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where': {
                'protocol': scan.protocol,
                'scanner_name': scan.scanner
            }}
        )]

    def get_ports_by_scan_and_node(self, node: 'Node', scan: 'Scan') -> list:
        """
        Get ports from database for given node and scan.

        """
        return self.select("ports_scans", node_id=node.id, node_ip=node.ip, scan_id=scan.rowid)

    def get_nodes_by_scan(self, scan: 'Scan') -> list:
        """
        Get nodes from database for given scan.

        """
        nodes = [el.node for el in self.select("nodes_scans", scan_id=scan.rowid)]

        for node in nodes:
            node.scan = scan

        return nodes

    def save_security_scan(self, exploit: 'Explot', port: 'Port', scan: 'Scan'):
        """
        Save scan of port by exploit to database
        """
        return self.execute(self._save_security_scan(exploit=exploit, port=port, scan=scan))

    def save_security_scans(self, exploits: list, port: 'Port', scan: 'Scan'):
        """
        Save scans of port to database basing on given exploits

        """
        return self.execute(self._save_security_scans(exploits=exploits, port=port, scan=scan))

    def get_security_scan_info(self, port: 'Port', app: str, scan: 'Scan') -> list:
        """
        Get security scan info from database

        """
        return self.select("security_scans", exploit_app=app, node_id=port.node.id, node_ip=port.node.ip,
                           port_protocol=port.transport_protocol, port_number=port.number,
                           join={'table': 'scans', 'from': 'scan_id', 'to': 'rowid', 'where':
                               {'protocol': scan.protocol, 'scanner_name': scan.scanner}})

    def security_scan_by_vuln(self, vuln):
        return self.select('security_scans', exploit_id=vuln.exploit.id, node_id=vuln.port.node.id,
                           node_ip=vuln.port.node.ip, port_protocol=vuln.port.transport_protocol,
                           port_number=vuln.port.number, scan_id=vuln.scan.rowid, limit=1)

    def next_security_scan(self, sec_scan):
        """
        Get security scan which finish after given

        """
        return self.select('security_scans', limit=1, exploit_id=sec_scan.exploit.id, node_id=sec_scan.port.node.id,
                           node_ip=sec_scan.port.node.ip, port_protocol=sec_scan.port.transport_protocol,
                           port_number=sec_scan.port.number, where={
                'operator': {
                    '>': {'sec_scan_end': sec_scan.scan_end}
                }})

    def save_changes(self, changes: list):
        """
        Save changes to database

        """
        return self.execute(self._save_changes(changes=changes))

    def clear_security_scans(self):
        """
        Clear broken scan details

        """
        return self.execute(self._clear_security_scans())

    def create_tables(self):
        """
        Create tables in storage

        """
        return self.execute(self._create_tables())

    def get_ports_by_nodes(self, nodes: list, pasttime: float = 0, timestamp: float = None,
                           protocol: 'TransportProtocol' = None, portdetection_only: bool = False):
        """
        Returns list of port for given list of nodes. protocol and portdetection_only has special meanings
        (in this order):
        * If portdetection_only is True, then function returns ports only from portdetection scans
        * If protocol is None then returns ports belonging to any protocol
        * If protocol is not None then returns ports only fot this protocol

        ToDo: Split on three different functions and validate usability of code paths

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
        for i in range(ceil(len(nodes) / self.nodes_limit)):
            yield {'or': [{'node_ip': node.ip, 'node_id': node.id}
                          for node in nodes[i * self.nodes_limit:(i + 1) * self.nodes_limit]],
                   'operator': {'>': {'time': timestamp}}}

    def _transport_protocol(self, number: int):
        """
        Convert database protocol to TransportProtocol

        """
        if number is None:
            return None

        return TransportProtocol.from_iana(number)

    def _protocol_to_iana(self, protocol: 'TransportProtocol') -> [int, None]:
        """
        Convert database protocol to TransportProtocol

        """
        if protocol is None:
            return None

        return protocol.iana

    def _save_scan(self, scan: 'Scan') -> tuple:
        """
        Queries for saving scan into database

        """
        return self.QUERY_SAVE_SCAN, (self._protocol_to_iana(scan.protocol), scan.scanner, scan.start, scan.end)

    def _update_scan(self, scan: 'Scan') -> tuple:
        return self.QUERY_UPDATE_SCAN_END, (scan.end, scan.rowid)

    def save_scan(self, scan: 'Scan') -> 'Scan':
        """
        Save scan into storage

        """
        result = self.execute([self._save_scan(scan=scan), self._get_last_rowid()])
        scan.rowid = result[1][0][0]
        return scan

    def update_scan(self, scan: 'Scan'):
        """
        Update scan in storage

        """
        return self.execute(self._update_scan(scan=scan))

    def get_scan_id(self, scan: 'Scan') -> int:
        """
        Get scan_id

        """
        if scan.rowid:
            return scan.rowid

        _scan = self.select("scans", limit=1, protocol=scan.protocol, scanner_name=scan.scanner, scan_start=scan.start)
        return _scan[0].rowid if _scan else None

    def get_scans(self, protocol: 'TransportProtocol', scanner_name: 'str', amount: int = 2) -> list:
        """
        Obtain scans from storage. Scans are taken from newest to oldest

        """
        return self.select("scans", protocol=protocol, limit=amount, scanner_name=scanner_name)

    def get_scans_by_node(self, node: 'Node', scan: 'Scan') -> list:
        """
        Obtain scans from storage based on given node and scan

        """
        return self.select("scans", limit=2, protocol=scan.protocol, scanner_name=scan.scanner, join={
            'table': 'nodes_scans',
            'from': 'rowid',
            'to': 'scan_id',
            'where': {'node_id': node.id, 'node_ip': node.ip}
        })

    def get_scans_by_security_scan(self, exploit: 'Exploit', port: 'Port') -> list:
        """
        Obtain scans from storage based on given exploit and port

        """
        return self.select(table='scans', join={'table': 'security_scans', 'from': 'rowid', 'to': 'scan_id', 'where': {
            'node_id': port.node.id, 'node_ip': port.node.ip, 'port_number': port.number,
            'port_protocol': port.transport_protocol, 'exploit_id': exploit.id, 'exploit_app': exploit.app,
            'exploit_name': exploit.name
        }})

    def get_scan_by_id(self, scan_id: int) -> Scan:
        """
        Obtain scan from storage

        """
        return self.scan_by_id(scan_id)

    def _save_vulnerabilities(self, vulnerabilities: list, scan: 'Scan') -> list:
        """
        Save vulnerabilities into local storage

        """
        scan_id = self.get_scan_id(scan)
        return [(self.QUERY_SAVE_VULNERABILITY, (scan_id, vuln.port.node.id, str(vuln.port.node.ip),
                                                 self._protocol_to_iana(vuln.port.transport_protocol), vuln.port.number,
                                                 vuln.exploit.id, vuln.subid, vuln.cve, vuln.cvss, vuln.output,
                                                 vuln.time))
                for vuln in vulnerabilities]

    def save_vulnerabilities(self, vulnerabilities: list, scan: 'Scan'):
        """
        Save vulnerabilities into local storage

        """
        return self.execute(self._save_vulnerabilities(vulnerabilities=vulnerabilities, scan=scan))

    def _scan_from_row(self, row: list) -> 'Scan':
        return Scan(start=row[3], end=row[4], protocol=self._transport_protocol(row[1]), scanner=row[2], rowid=row[0])

    def _nodes_scan_from_row(self, row: list) -> 'NodeScan':
        return NodeScan(node=Node(node_id=row[1], ip=ipaddress.ip_address(row[2])), rowid=row[0], timestamp=row[4],
                        scan=self.get_scan_by_id(row[3]))

    def _port_scan_from_row(self, row: list) -> 'PortScan':
        return PortScan(port=Port(node=Node(node_id=row[1], ip=ipaddress.ip_address(row[2])),
                                  number=row[4], transport_protocol=TransportProtocol.from_iana(row[5])),
                        rowid=row[0],
                        timestamp=row[6],
                        scan=self.get_scan_by_id(row[3]))

    def _vulnerability_from_row(self, row: list) -> 'Vulnerability':
        vuln = Vulnerability(port=Port(transport_protocol=self._transport_protocol(row[4]), number=row[5],
                                       node=Node(node_id=row[2], ip=ipaddress.ip_address(row[3]))),
                             exploit=Exploit(exploit_id=row[6]), subid=row[7], cve=row[8], cvss=row[9], output=row[10],
                             vuln_time=row[11], rowid=row[0], scan=self.get_scan_by_id(row[1]), expiration_time=row[12])

        sec_scans = self.security_scan_by_vuln(vuln)

        if not sec_scans:
            log.error('Cannot find security scan for given vulnerability')
            return vuln

        sec_scan = sec_scans[0]
        vuln.port.scan = Scan(start=sec_scan.scan_start, end=sec_scan.scan_end, scanner=vuln.scan.scanner)
        return vuln

    def _sec_scan_from_row(self, row: list) -> SecurityScan:
        return SecurityScan(port=Port(node=Node(node_id=row[5], ip=ipaddress.ip_address(row[6])),
                                      transport_protocol=self._transport_protocol(row[7]), number=row[8]),
                            rowid=row[0], scan=self.get_scan_by_id(row[1]), scan_start=row[9], scan_end=row[10],
                            exploit=Exploit(exploit_id=row[2], app=row[3], name=row[4]))

    def scans_by_node_scan(self, node_scan: 'NodeScan') -> list:
        """
        Return list of scans related to given NodeScan

        """
        return self.select('scans', 30, 0, join={'from': 'rowid', 'to': 'scan_id', 'table': 'nodes_scans', 'where': {
            'node_id': node_scan.node.id,
            'node_ip': str(node_scan.node.ip),
        }})

    def scans_by_port_scan(self, port_scan: 'PortScan') -> list:
        """
        Return list of scans related to given PortScan

        """
        return self.select('scans', 30, 0, join={'from': 'rowid', 'to': 'scan_id', 'table': 'ports_scans', 'where': {
            'node_id': port_scan.node.id,
            'node_ip': port_scan.node.ip,
            'port': port_scan.port.number,
            'port_protocol': port_scan.port.transport_protocol
        }})

    def nodes_scans_by_scan(self, scan: 'Scan') -> list:
        """
        Return list of NodeScan for given Scan

        """
        return self.select("nodes_scans", scan_id=scan.rowid)

    def ports_scans_by_scan(self, scan: 'Scan') -> list:
        """
        Return list of PortScan for given Scan

        """
        return self.select("ports_scans", scan_id=scan.rowid)

    def save_node_scan(self, node_scan: 'NodeScan') -> 'NodeScan':
        """
        Save NodeScan to the storage. Returns NodeScan with updated ROWID

        """
        result = self.execute([
            self._save_node(node_scan.node, node_scan.scan, timestamp=node_scan.timestamp),
            self._get_last_rowid()
        ])
        node_scan.rowid = result[1][0][0]
        return node_scan

    def save_port_scan(self, port_scan: 'PortScan'):
        """
        Save PortScan to the storage. Returns PortScan with updated ROWID

        """
        self.execute(self._save_port(port_scan.port, port_scan.scan, timestamp=port_scan.timestamp))

    def save_sec_scan(self, sec_scan: 'SecurityScan') -> 'SecurityScan':
        """
        Save SecurityScan to the storage. Returns SecurityScan with updated rowid

        """
        result = self.execute([
            (self.QUERY_SAVE_SECURITY_SCAN, (sec_scan.scan.rowid, sec_scan.exploit.id, sec_scan.exploit.app,
                                             sec_scan.exploit.name, sec_scan.node.id, str(sec_scan.node.ip),
                                             self._protocol_to_iana(sec_scan.port.transport_protocol),
                                             sec_scan.port.number, sec_scan.scan_start, sec_scan.scan_end)),
            self._get_last_rowid()
        ])

        sec_scan.rowid = result[1][0][0]
        return sec_scan

    def scans_by_security_scan(self, sec_scan: 'SecurityScan') -> list:
        """
        Returns scans for given SecurityScan

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

    def scans_by_vulnerability(self, vuln: 'Vulnerability') -> list:
        """
        Returns scans for given vulnerability

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

    def save_vulnerability(self, vuln: 'Vulnerability'):
        """
        Save vulnerability into storage

        """
        self.execute((self.QUERY_SAVE_VULNERABILITY, (vuln.scan.rowid, vuln.port.node.id, str(vuln.port.node.ip),
                                                      self._protocol_to_iana(vuln.port.transport_protocol),
                                                      vuln.port.number,
                                                      vuln.exploit.id, vuln.subid, vuln.cve, vuln.cvss, vuln.output,
                                                      vuln.time)))

    def expire_vulnerability(self, vuln: 'Vulnerability') -> 'Vulnerability':
        """
        Set vulnerability expiration time:

        1. Get security scan related to given vulnerability
        2. Get next security scan after obtained
        3. If next security scan exists, it means that given vulnerability is no longer actual

        """
        curr_sec_scans = self.security_scan_by_vuln(vuln)

        if not curr_sec_scans:
            log.error('Cannot find security scan for given vulnerability')
            return vuln

        curr_sec_scan = curr_sec_scans[0]

        next_sec_scans = self.next_security_scan(curr_sec_scan)

        if not next_sec_scans:
            return vuln

        next_sec_scan = next_sec_scans[0]

        vuln.expiration_time = next_sec_scan.scan_start
        self.execute(
            (self.QUERY_UPDATE_VULNERABILITY_EXPIRATION, (vuln.expiration_time, vuln.scan.rowid, vuln.port.node.id,
                                                          str(vuln.port.node.ip),
                                                          self._protocol_to_iana(vuln.port.transport_protocol),
                                                          vuln.port.number, vuln.exploit.id, vuln.subid)))

        return vuln

    def active_vulnerabilities(self) -> list:
        """
        Gets all vulnerabilites with unset expiration time
        """
        return self.select('vulnerabilities', expiration_time=None)

    def expire_vulnerabilities(self):
        """
        Checks if any of vulnerability should be expired and do it if needed. Returns expired vulnerabilities

        """
        vulns = self.active_vulnerabilities()
        log.debug('%s active vulnerabilities to check', len(vulns))

        for vuln in vulns:
            self.expire_vulnerability(vuln)

        log.debug('Left %s active vulnerabilities', len([vuln for vuln in vulns if vuln.expiration_time is None]))

        return [vuln for vuln in vulns if vuln.expiration_time is not None]

    def portdetection_vulns(self, vuln: 'Vulnerability'):
        """
        Returns dict which describes service details (name, version, application name, banner) for given vulnerability

        """
        return_value = {
            'protocol': None,
            'name': None,
            'version': None,
            'banner': None,
            'cpe': None,
            'os_name': None,
            'os_version': None,
            'os_cpe': None
        }

        vulnerabilities = self.select(table='vulnerabilities', node_id=vuln.port.node.id, node_ip=vuln.port.node.ip,
                                      port=vuln.port.number, port_protocol=vuln.port.transport_protocol,
                                      vulnerability_id=0, scan_id=vuln.scan.rowid)

        for vulnerability in vulnerabilities:
            if vulnerability.subid == Vulnerability.SERVICE_PROTOCOL:
                return_value['protocol'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.SERVICE_NAME:
                return_value['name'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.SERVICE_VERSION:
                return_value['version'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.SERVICE_BANNER:
                return_value['banner'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.SERVICE_CPE:
                return_value['cpe'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.OS_NAME:
                return_value['os_name'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.OS_VERSION:
                return_value['os_version'] = vulnerability.output
            elif vulnerability.subid == Vulnerability.OS_CPE:
                return_value['os_cpe'] = vulnerability.output

        return return_value

    def remove_all(self):
        for key in self.TABLES:
            self.execute(('DROP TABLE IF EXISTS {}'.format(key), ))

        self.execute(('DROP TABLE IF EXISTS changes',))