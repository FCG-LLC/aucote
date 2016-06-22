from utils.database import DbBase

class ScanDb(DbBase):
    '''
    Inserts data from a performed scan
    '''

    def insert_scan(self, start):
        '''
        Inserts a new scan.
        Args:
            start(datetime) - timestamp of the start of te given scan
            start(datetime) - timestamp of the end of te given scan
        Returns:
            integer ID of inserted scan
        '''
        data = {
            'start': start
        }
        db_id =  self.insert('scans', data, 'id')
        self.commit()
        return db_id

    def update_scan(self, scan_id, end):
        self.cur.execute('UPDATE scans SET "end" = %s WHERE id=%s', (end, scan_id))
        self.commit()

    def insert_port(self, port, scan_id):
        data = {
            'scan_id': scan_id,
            'number': port.number,
            'ip': str(port.node.ip),
            'transport_protocol': port.transport_protocol.name,
            'device_id': port.node.id,
            'service_name': port.service_name,
            'service_version': port.service_version,
            'banner': port.banner,
        }
        db_id = self.insert('ports', data, 'id')
        self.commit()
        return db_id

    def insert_vulnerability(self, vulnerability):
        data = {
        'port_id': vulnerability.port.db_id,
        'title': vulnerability.title,
        'description': vulnerability.description,
        'risk_level': vulnerability.risk_level.value,
        }
        db_id = self.insert('vulnerabilities', data)
        self.commit()
        return db_id
