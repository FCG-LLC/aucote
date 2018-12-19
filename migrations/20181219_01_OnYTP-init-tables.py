"""
Init tables
"""

from yoyo import step

__depends__ = {}

steps = [
    step("CREATE TABLE IF NOT EXISTS scans(rowid SERIAL UNIQUE, protocol int, scanner_name VARCHAR, scan_start int, "
         "scan_end int, UNIQUE (protocol, scanner_name, scan_start))"),

    step("CREATE TABLE IF NOT EXISTS nodes_scans(rowid SERIAL UNIQUE, scan_id int, node_id BIGINT, node_ip text, "
         "time int, primary key (scan_id, node_id, node_ip))"),

    step("CREATE TABLE IF NOT EXISTS ports_scans (rowid SERIAL UNIQUE, scan_id int, node_id BIGINT, node_ip text, "
         "port int, port_protocol int, time int, primary key (scan_id, node_id, node_ip, port, port_protocol))"),

    step("CREATE TABLE IF NOT EXISTS security_scans (rowid SERIAL UNIQUE, scan_id int, exploit_id int, "
         "exploit_app text, exploit_name text, node_id BIGINT, node_ip text, port_protocol int, port_number int, "
         "sec_scan_start float, sec_scan_end float, PRIMARY KEY (scan_id, exploit_id, node_id, node_ip, "
         "port_protocol, port_number))"),

    step("CREATE TABLE IF NOT EXISTS vulnerabilities(rowid SERIAL UNIQUE, scan_id int, node_id BIGINT, "
         "node_ip text, port_protocol int, port int, vulnerability_id int, vulnerability_subid int, cve text, "
         "cvss text, output text, time int, expiration_time int, primary key(scan_id, node_id, "
         "node_ip, port_protocol, port, vulnerability_id, vulnerability_subid))"),

    step("CREATE TABLE IF NOT EXISTS changes(rowid SERIAL PRIMARY KEY, type int, vulnerability_id int, "
         "vulnerability_subid int, previous_id int null, current_id int null, time int, UNIQUE(type, "
         "vulnerability_id, vulnerability_subid, previous_id, current_id, time))"),
]
