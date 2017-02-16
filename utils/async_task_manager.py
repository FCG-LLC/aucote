"""
This module contains class for managing async tasks.

"""
from tornado import gen
from tornado.ioloop import IOLoop
from tornado.locks import Event


class AsyncTaskManager(object):
    """
    Aucote uses asynchronous task executed in ioloop. Some of them,
    especially scanners, should finish before ioloop will stop

    """
    _SHUTDOWN_CONDITION = Event()
    _CRON_TASKS = {}
    _RUN_TASKS = {}

    @classmethod
    def start(cls):
        """
        Start CronTabCallback tasks

        Returns:
            None

        """
        for task in cls._CRON_TASKS.values():
            task.start()

    @classmethod
    def add_task(cls, name, task):
        """
        Add cron task. name is name of function, task is CronTabCallback object

        Args:
            name (str): function/method name
            task (CronTabCallback):

        Returns:
            None

        """
        cls._CRON_TASKS[name] = task
        cls._RUN_TASKS[name] = False

    @classmethod
    @gen.coroutine
    def stop(cls):
        """
        Stop CronTabCallback tasks and wait on them to finish

        Returns:
            None

        """
        for task in cls._CRON_TASKS.values():
            task.stop()
        IOLoop.current().add_callback(cls.monitor_ioloop_shutdown)
        yield [cls._SHUTDOWN_CONDITION.wait()]

    @classmethod
    def lock_task(cls, function):
        """
        Decorator which aloow execution only one instance of function at same time

        Args:
            function:

        Returns:
            function

        """
        @gen.coroutine
        def return_function(*args, **kwargs):
            """
            Wrapper on original function

            Args:
                *args:
                **kwargs:

            Returns:
                None

            """
            if cls._RUN_TASKS[function.__name__]:
                return
            cls._RUN_TASKS[function.__name__] = True

            yield function(*args, **kwargs)

            cls._RUN_TASKS[function.__name__] = False

        return return_function

    @classmethod
    def monitor_ioloop_shutdown(cls):
        """
        Check if ioloop can be stopped

        Returns:
            None

        """
        if any([task.is_running() for task in cls._CRON_TASKS.values()]) or any(cls._RUN_TASKS.values()):
            IOLoop.current().add_callback(cls.monitor_ioloop_shutdown)
            return

        cls._SHUTDOWN_CONDITION.set()

    @classmethod
    def clear(cls):
        """
        Clear list of tasks

        Returns:
            None

        """
        cls._CRON_TASKS = {}
        cls._RUN_TASKS = {}
