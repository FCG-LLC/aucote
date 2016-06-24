from utils.database import DbBase

class ApiDb(DbBase):
    '''
    Retrieves data for the API.
    '''

    def get_scans(self):
        result = []
        for row in self.fetch_all('SELECT id, start, "end" FROM scans WHERE "end" IS NOT NULL ORDER BY start DESC'):
            scan = {
                'id': row[0],
                'start': row[1].isoformat(),
                'end': row[2].isoformat()
            }
            result.append(scan)
        return result

    def get_newest_scan(self):
        rows = list(self.fetch_all('SELECT id FROM scans WHERE "end" IS NOT NULL ORDER BY start DESC LIMIT 1'))
        if len(rows) != 1: return None
        return rows[0][0]

    def get_ports(self, scan_id):
        result = []
        for row in self.fetch_all('SELECT id, "number", transport_protocol, host(ip), device_id, service_name, service_version, banner FROM ports WHERE scan_id = %s', (scan_id,)):
            port = {
                'id': row[0],
                'number': row[1],
                'protocol': row[2],
                'ip': row[3],
                'deviceId': row[4],
                'serviceName': row[5],
                'serviceVersion': row[6],
                'banner': row[7]
            }
            result.append(port)
        return result

    def get_vulnerabilities(self, scan_id, port_id):
        result = []
        query = '''SELECT v.id, v.port_id, e.title, e.description, e.risk_level FROM vulnerabilities v 
            LEFT JOIN ports p ON v.port_id = p.id 
            LEFT JOIN exploits e ON v.exploit_id = e.id
            WHERE '''
        conditions = []
        args = []
        if scan_id is not None:
            conditions.append('p.scan_id = %s')
            args.append(scan_id)
        if port_id is not None:
            conditions.append('p.id =%s')
            args.append(port_id)
        query += ' AND '.join(conditions)
        for row in self.fetch_all(query, *args):
            port = {
                'id': row[0],
                'portId': row[1],
                'title': row[2],
                'description': row[3],
                'riskLevel': row[4]
            }
            result.append(port)
        return result

    def get_exploits(self):
        result = []
        for row in self.fetch_all('SELECT id, app, name, title, description, risk_level FROM exploits'):
            result.append({
                'id': row[0],
                'app': row[1],
                'name': row[2],
                'title': row[3],
                'description': row[4],
                'riskLevel': row[5]
                })
        return result


