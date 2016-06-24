from utils.database import DbBase
import psycopg2

class MigrationDb(DbBase):
    '''
    Retrieves data for the API.
    '''


    def sync_exploit(self, app, name, title, description, risk_level):
        data = {
            'app': app,
            'name': name,
            'title': title,
            'description': description,
            'risk_level': risk_level
        }
        try:
            self.insert('exploits', data)
        except psycopg2.IntegrityError:
            #duplicate, update
            self.conn.rollback()
            self.cur.execute('UPDATE exploits SET title=%s, description=%s, risk_level=%s WHERE app=%s AND name=%s', (title, description, risk_level, app, name)) 
        self.commit()
        