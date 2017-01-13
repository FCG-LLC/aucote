"""
This module contains Task responsible for local store managing

"""
import logging as log
from queue import Queue, Empty

import time

from utils.storage import Storage
from utils.task import Task


class StorageTask(Task):
    """
    This task queues queries and execute them in order

    """
    def __init__(self, filename=":memory:", *args, **kwargs):
        """
        Init values

        Args:
            filename (str):
            *args:
            **kwargs:

        """
        super(StorageTask, self).__init__(*args, **kwargs)
        self.filename = filename
        self._queue = Queue()
        self._storage = Storage(self, self.filename)
        self._storage.connect()
        self.executor.storage = self._storage

    def __call__(self, *args, **kwargs):
        """
        Run infinite loop. while loop takes queries from queue and execute them

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        self._storage.clear_scan_details()
        while True:
            if self.executor.unfinished_tasks == 1 and self.executor.started:
                log.debug("No more tasks for executing. auto-destroying storage task.")
                self.executor.storage = None
                break

            try:
                query = self._queue.get(timeout=10)
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
