"""
Provide class for tasks

"""
from utils.storage import Storage


class Task(object):
    """
    Base class for tasks, e.g. scan, nmap, hydra

    """
    def __init__(self, executor):
        """
        Assign executor

        """
        self.executor = executor

    @property
    def kudu_queue(self):
        """
        Return executors kudu_queue

        """
        return self.executor.kudu_queue

    @property
    def exploits(self):
        """
        Return executors exploits

        """
        return self.executor.exploits

    def __call__(self, *args, **kwargs):
        """
        Call executed by executor

        """
        raise NotImplementedError

    def send_msg(self, msg):
        """
        Send msg to kudu_queue

        """
        return self.kudu_queue.send_msg(msg)

    def store_scan_end(self, exploits, port):
        """
        Stores scan end in local storage

        Args:
            exploits (Exploits):
            port (Port):

        Returns:
            None
        """
        with Storage(filename=self.executor.storage.filename) as storage:
            for exploit in exploits:
                storage.save_scan(exploit=exploit, port=port, scan_end=port.scan.end)
