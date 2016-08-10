"""
Database related code
"""

import logging as log
import psycopg2
import yoyo


class DbBase:
    """
    Base class for components that make connection to PostgreSQL database
    """

    conn = None
    cur = None

    def __init__(self, db_config):
        self._cfg = db_config

    def __enter__(self):
        """
        connect to database while enters in "with" statement
        """
        self.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """
        disconnect from database while exits from "with" statement
        """
        self.close()

    def close(self):
        """
        Close connection to database.

        """
        if self.conn is None:
            return
        self.conn.close()
        self.conn = None
        self.cur = None

    def commit(self):
        """
        Commit changes to database
        """
        self.conn.commit()

    def connect(self):
        """
        Makes a PostgreSQL connection from provided configuration dictionary.
        """
        if self.conn:
            #close and reconnect
            self.close()
        conn_str = "user='%s' password='%s' host='%s' port='%s' dbname='%s'"%(
            self._cfg['user'],
            self._cfg['password'],
            self._cfg['host'],
            self._cfg['port'],
            self._cfg['database'])
        self.conn = psycopg2.connect(conn_str)
        self.cur = self.conn.cursor()

    def fetch_all(self, query, *args):
        """
        Execute query and fetch all rows
        """
        self.cur.execute(query, args)
        return self.cur.fetchall()

    def insert(self, table, values_dict, returning=None):
        """
        Shortcut for single inserts. Inserts a row into table.
        """
        try:
            columns = list(values_dict)
            values = [values_dict[key] for key in columns]
            val_str = ('%s,'*len(values_dict))[:-1]
            sql = 'INSERT INTO %s (%s) VALUES(%s)'%(table, ','.join(columns), val_str)
            if returning:
                sql = '%s RETURNING %s'%(sql, returning)
            #print('executing', sql)
            self.cur.execute(sql, values)
            if returning:
                row = self.cur.fetchone()
                return row[0]
        except:
            log.warning('Exception while inserting data into %s table, data: %s', table, values_dict)
            raise


class DbObject:
    """
    Base class for objects that need to be saved and read from a database.
    """
    db_id = None
    TABLE = None
    MAPPING = None


class MigrationManager:
    """
    Performs execution of migrations.
    """
    def __init__(self, db_config, migration_path):
        self._db_config = db_config
        self._migration_path = migration_path

    def migrate(self):
        """
        Runs the migration process
        """
        print('Migrating...')
        connect_str = 'postgres://%s:%s@%s:%s/%s'%(
            self._db_config['user'],
            self._db_config['password'],
            self._db_config['host'],
            self._db_config['port'],
            self._db_config['database'])
        backend = yoyo.get_backend(connect_str)
        all_migrations = yoyo.read_migrations(self._migration_path)
        migrations = backend.to_apply(all_migrations)
        print('Applying', len(migrations), 'migrations:')
        for migr in migrations:
            print('->', migr.id)
        backend.apply_migrations(migrations)
        print('Migrations done. Exiting.')
