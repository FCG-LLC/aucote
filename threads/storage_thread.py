"""
Thread responsible for local storage

"""
from threading import Thread, Event, Lock
import logging as log
from queue import Queue, Empty

from utils.storage import Storage


class StorageThread(Thread):
    """
    Thread for creating and managing in-memory storage using a Queue.

    """
    def __init__(self, storage: Storage):
        super(StorageThread, self).__init__()
        self._storage = storage
        self.name = "Storage"
        self._queue = Queue()
        self.lock = Lock()
        self.started_event = Event()
        self._close = False

    def __enter__(self):
        self.start()
        self.started_event.wait()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        self.join()

    def run(self):
        """
        Connect to the storage and execute queries from queue in infinite loop
        """
        with self._storage:
            self._storage.set_thread(self)
            self.started_event.set()

            while not self._close or not self._queue.empty():
                try:
                    query = self._queue.get(timeout=1)
                except Empty:
                    continue

                with self.lock:
                    try:
                        query['result'] = self._storage.execute(query['query'])
                        self._queue.task_done()
                        query['event'].set()
                    except Exception as exception:
                        query['result'] = exception

        log.debug("Exit")

    def execute(self, query):
        """
        Adds query to the queue.
        """
        event = Event()
        query = {
            'event': event,
            'query': query,
            'result': None
        }
        self._queue.put(query)
        event.wait()

        with self.lock:
            if isinstance(query['result'], Exception):
                raise query['result']

            return query['result']

    def stop(self):
        self._close = True
