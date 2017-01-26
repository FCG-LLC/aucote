"""
Thread responsible for local storage

"""

from threading import Thread

import logging as log
from queue import Queue, Empty

from structs import StorageQuery
from utils.storage import Storage


class StorageThread(Thread):
    """
    Class which is separate thread. Creates and manages local storage

    """
    def __init__(self, filename):
        super(StorageThread, self).__init__()
        self.name = "Storage"
        self.filename = filename
        self._queue = Queue()
        self._storage = Storage(self, self.filename)
        self.finish = False

    def run(self):
        """
        Run infinite loop. while loop takes queries from queue and execute them

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        self._storage.connect()
        self._storage.clear_scan_details()
        while not self.finish:
            try:
                query = self._queue.get(timeout=1)
            except Empty:
                continue

            if isinstance(query, list):
                log.debug("executing %i queries", len(query))
                for row in query:
                    self._storage.cursor.execute(*row)
            elif isinstance(query, StorageQuery):
                try:
                    query.result = self._storage.cursor.execute(*query.query).fetchall()
                except Exception:
                    log.exception("Exception while executing query: %s", query.query[0])
                finally:
                    query.lock.release()
                    self._queue.task_done()
                continue
            else:
                log.debug("executing query: %s", query[0])
                self._storage.cursor.execute(*query)
            self._storage.conn.commit()
            self._queue.task_done()
        self._storage.close()
        log.debug("Exit")

    def add_query(self, query):
        """
        Adds query to the queue

        Args:
            query:

        Returns:
            returns query
        """
        self._queue.put(query)
        return query

    def stop(self):
        """
        Stop thread

        Returns:
            None

        """
        log.info("Stopping storage")
        self.finish = True

    @property
    def storage(self):
        """
        Handler to local storage

        Returns:
            Storage

        """
        return self._storage

    def get_info(self):
        """
        Informations about storage status

        Returns:
            dict

        """
        return {
            'path': self.filename,
        }
