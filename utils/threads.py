"""
File containing Threads-related functionality
"""
from queue import Queue
import logging as log
from threading import Thread, Lock
import time


class Worker(Thread):
    """
    Worker responsible for executing task from ThreadPool task queue

    """
    def __init__(self, queue, *args, **kwargs):
        super(Worker, self).__init__(*args, **kwargs)
        self._task = None
        self._lock = Lock()
        self._queue = queue

    def run(self):
        while True:
            task = self._queue.get()

            if task is None:
                log.debug("finishing thread.")
                self.task = None
                self._queue.task_done()
                return

            self.task = task
            self.task.start_time = time.time()

            try:
                log.debug("Task %s starting", task)
                start_time = time.monotonic()
                task()
                log.debug('Task %s finished, took %s seconds. %i task left', task, time.monotonic() - start_time,
                          self._queue.unfinished_tasks)
            except Exception:
                log.exception('Exception while running %s', task)
            finally:
                self.task = None
                self._queue.task_done()

    @property
    def task(self):
        """
        Currently executing task

        Returns:

        """
        with self._lock:
            return self._task

    @task.setter
    def task(self, val):
        with self._lock:
            self._task = val

    @property
    def start_time(self):
        """
        Current task execution start time

        Returns:

        """
        with self._lock:
            return self._start_time

    @start_time.setter
    def start_time(self, val):
        with self._lock:
            self._start_time = val


class ThreadPool(object):
    """
    Provides a pool of threads and a queue to execute callable tasks.
    """

    def __init__(self, num_threads=1, name='Worker'):
        """
        Args:
            num_threads(int) - number of threads in the pool
        """
        self._lock = Lock()
        self._queue = Queue() #thread safe
        self._threads = []
        self._num_threads = num_threads
        self._name = name

    def add_task(self, task):
        """
        Add thread task to queue

        """
        self._queue.put(task)

    def start(self):
        """
        Start threads
        """
        self.threads = [Worker(queue=self._queue) for _ in range(0, self._num_threads)]
        for num, thread in enumerate(self._threads):
            thread.name = "%s%02d"%(self._name, num)
            thread.daemon = True
            thread.start()

    def stop(self):
        """
        Stop threads by sending end-the-work signal

        """
        for _ in self._threads:
            self._queue.put(None)
        for thread in self._threads:
            thread.join()
        self._threads = []

    def join(self):
        """
        Join to the threads

        """
        self._queue.join()

    @property
    def unfinished_tasks(self):
        """
        Returns number of unfinished tasks

        Returns:
            int

        """
        return self._queue.unfinished_tasks

    @property
    def num_threads(self):
        """
        Number of used threads

        Returns:
            int
        """
        return self._num_threads

    @property
    def threads(self):
        """
        List of threads

        Returns:
            list

        """
        with self._lock:
            return self._threads[:]

    @threads.setter
    def threads(self, val):
        with self._lock:
            self._threads = val

    @property
    def task_queue(self):
        """
        List of task waiting in queue

        Returns:
            list

        """
        with self._lock:
            return list(self._queue.queue)
