"""
Scans and ports tables
"""

from yoyo import step

__depends__ = {}

steps = [
    step('''
        CREATE TABLE scans (
            id SERIAL,
            start TIMESTAMP NOT NULL,
            "end" TIMESTAMP,
            PRIMARY KEY (id)
            )
        ''', '''
        DROP TABLE scans
    '''), step('''
        CREATE TYPE transport_protocol_type AS ENUM('TCP', 'UDP', 'ICMP')
        ''','''
        DROP TYPE transport_protocol_type
    '''),step('''
        CREATE TABLE ports (
            id SERIAL,
            scan_id  INTEGER NOT NULL,
            number INTEGER NOT NULL,
            ip INET NOT NULL,
            transport_protocol transport_protocol_type NOT NULL,
            device_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            service_version TEXT,
            banner TEXT,
            CONSTRAINT fk_scan FOREIGN KEY (scan_id)
            REFERENCES scans (id),
            PRIMARY KEY (id)
            )
        ''','''
            DROP TABLE ports
    '''), step('''
        CREATE TYPE risk_level_type AS ENUM('High', 'Medium', 'Low', 'None')
        ''','''
        DROP TYPE risk_level_type
    '''),step('''
        CREATE TABLE vulnerabilities (
            id SERIAL,
            port_id INTEGER,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_level risk_level_type NOT NULL DEFAULT 'Medium',
            CONSTRAINT fk_port FOREIGN KEY (port_id)
            REFERENCES ports (id),
            PRIMARY KEY (id)
            )
        ''', '''
        DROP TABLE vulnerabilities
    ''')
]
