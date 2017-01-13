from threading import Thread

import logging as log
from queue import Queue, Empty

import time

from utils.storage import Storage
from utils.task import Task


class StorageThread(Thread):

    def __init__(self, filename, aucote):
        super(StorageThread, self).__init__()
        self.aucote = aucote
        self.name = "Storage"
        self.filename = filename
        self._queue = Queue()
        self._storage = Storage(self, self.filename)
        self.aucote.storage = self._storage
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
        while True:
            if self.finish:
                log.debug("Exit")
                self.aucote.storage = None
                break

            try:
                query = self._queue.get(timeout=1)
            except Empty:
                continue

            if isinstance(query, list):
                log.debug("executing %i queries", len(query))
                for row in query:
                    self._storage.cursor.execute(*row)
            else:
                log.debug("executing query: %s", query[0])
                self._storage.cursor.execute(*query)
            self._storage.conn.commit()
            self._queue.task_done()
        self._storage.close()

    def add_query(self, query):
        """
        Adds query to the queue

        Args:
            query:

        Returns:
            None

        """
        self._queue.put(query)

    def stop(self):
        log.info("Stopping storage")
        self.finish = True