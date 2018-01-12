"""
Thread responsible for local storage

"""
from threading import Thread, Event, Lock
import logging as log
from queue import Queue, Empty

from utils.storage import Storage


class StorageThread(Thread):
    """
    Class which is separate thread. Creates and manages local storage

    """
    def __init__(self, storage: Storage):
        super(StorageThread, self).__init__()
        self._storage = storage
        self.name = "Storage"
        self._queue = Queue()
        self.finish = False
        self.lock = Lock()
        self.started_event = Event()

    def run(self):
        """
        Connect to the storage and execute queries from queue in infinite loop
        """
        self._storage.set_thread(self)

        self._storage.connect()
        self.started_event.set()

        while not self.finish:
            try:
                query = self._queue.get(timeout=1)
            except Empty:
                continue

            with self.lock:
                query['result'] = self._storage.execute(query['query'])
                self._queue.task_done()
                query['event'].set()

        self._storage.close()
        log.debug("Exit")

    def execute(self, query):
        """
        Adds query to the queue.
        """
        with self.lock:
            event = Event()
            query = {
                'event': event,
                'query': query,
                'result': None
            }
        self._queue.put(query)
        event.wait()

        with self.lock:
            return query['result']
