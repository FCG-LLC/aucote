from queue import Queue
import logging as log
from threading import Thread
import time


class ThreadPool:
    """
    Provides a pool of threads and a queue to execute callable tasks.
    """

    def __init__(self, num_threads=1, name='Worker'):
        """
        Args:
            num_threads(int) - number of threads in the pool
        """
        self._queue = Queue() #thread safe
        self._threads = []
        self._num_threads = num_threads
        self._name = name

    def add_task(self, task):
        self._queue.put(task) #_queue is thread safe

    def start(self):
        self._threads = [Thread(target=self._worker) for _ in range(0, self._num_threads)]
        for num, thread in enumerate(self._threads):
            thread.name = "%s%02d"%(self._name,num)
            thread.deamon = True
            thread.start()

    def stop(self):
        for _ in self._threads:
            self._queue.put(None) #send end-the-work signal
        for thread in self._threads:
            thread.join()
        self._threads = []

    def join(self):
        self._queue.join()

    def _worker(self):
        while True:
            task = self._queue.get()
            if task is None:
                log.debug("No more tasks in the queue to execute, finishing thread.")
                return
            try:
                log.debug("Task %s starting", task)
                start_time = time.monotonic()
                task()
                log.debug('Task %s finished, took %s seconds', task, time.monotonic() - start_time)
            except Exception as err:
                log.error('Exception %s while running %s', err, task, exc_info=err)
            finally:
                self._queue.task_done()
