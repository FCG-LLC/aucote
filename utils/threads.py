"""
File containing Threads-related functionality
"""
from queue import Queue, Empty
import logging as log
from threading import Thread
import time


class ThreadPool(object):
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
        self._finish = False

    def add_task(self, task):
        """
        Add thread task to queue

        """
        self._queue.put(task)

    def start(self):
        """
        Start threads
        """
        self._finish = False
        self._threads = [Thread(target=self._worker, args=[number]) for number in range(0, self._num_threads)]
        for num, thread in enumerate(self._threads):
            thread.name = "%s%02d"%(self._name, num)
            thread.task = None
            thread.daemon = True
            thread.start()

    def stop(self):
        """
        Stop threads by sending end-the-work signal

        """
        self._finish = True

        for thread in self._threads:
            thread.join()
        self._threads = []

    def join(self):
        """
        Join to the threads

        """
        self._queue.join()

    def _worker(self, number):
        while self.unfinished_tasks or not self._finish:
            try:
                task = self._queue.get(timeout=10)
                self._threads[number].task = task
                self._threads[number].start_time = time.time()
            except Empty:
                continue

            try:
                log.debug("Task %s starting", task)
                start_time = time.monotonic()
                task()
                log.debug('Task %s finished, took %s seconds. %i task left', task, time.monotonic() - start_time,
                          self._queue.unfinished_tasks)
            except Exception:
                log.exception('Exception while running %s', task)
            finally:
                self._queue.task_done()
                self._threads[number].task = None
                self._threads[number].start_time = None

        log.debug("finishing thread.")

    @property
    def unfinished_tasks(self):
        """
        Returns number of unfinished tasks

        Returns:
            int

        """
        return self._queue.unfinished_tasks

    @property
    def stats(self):
        """
        Simple statistics

        Returns:
            Dict with simple statistics
        """
        return_value = {'queue': [], 'threads': []}

        for thread in self._threads:
            if thread.task is None:
                continue
            return_value['threads'].append(self.get_thread_info(thread))

        for task in self._queue.queue:
            return_value['queue'].append(self.get_task_info(task))

        return_value['queue_length'] = len(return_value['queue'])
        return_value['threads_length'] = len(return_value['threads'])

        return return_value

    @classmethod
    def get_task_info(cls, task):
        return {
            'type': type(task).__name__,
            'data': task.get_info(),
            'start': task.start
        }

    @classmethod
    def get_thread_info(cls, thread):
        return_value = cls.get_task_info(thread.task)
        return_value['start_time'] = thread.start_time
        return_value['duration'] = time.time() - thread.start_time

        return return_value
