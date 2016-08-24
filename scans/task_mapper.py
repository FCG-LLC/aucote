"""make install
Class responsible for mapping scans and port, service
"""
from scans.executor_config import EXECUTOR_CONFIG


class TaskMapper:
    """
    Assign tasks for a provided port
    """

    def __init__(self, executor):
        self._executor = executor

    def assign_tasks(self, port):
        """
        Assign tasks for a provided port
        """

        scripts = self._executor.exploits.find_all(port)
        for app, exploits in scripts.items():
            task = EXECUTOR_CONFIG['apps'][app]['class'](executor=self._executor, exploits=exploits, port=port,
                                                         config=EXECUTOR_CONFIG['apps'][app])
            task()

    @property
    def exploits(self):
        """
        Executor's exploits
        """
        return self._executor.exploits
