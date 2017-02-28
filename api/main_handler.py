"""
Handler responsible for returning status of aucote

"""
import time

from api.handler import Handler
from aucote_cfg import cfg
from scans.executor import Executor
from tools.base import Tool
from tools.common.port_task import PortTask
from utils.task import Task


class MainHandler(Handler):
    """
    Handler responsible for returning status of aucote

    """
    def get(self):
        """
        Handle get method and returns aucote status in JSON

        Returns:
            None - writes aucote status in JSON

        """
        self.write(self.aucote_status())

    def aucote_status(self):
        """
        Get current status of aucote tasks

        Returns:
            dict

        """
        stats = self.thread_pool_status(self.aucote.thread_pool)
        stats['scanner'] = self.scanning_status(self.aucote.scan_task)
        stats['meta'] = self.metadata()
        return stats

    @classmethod
    def metadata(cls):
        """
        Meta of API request

        Returns:
            dict
        """
        return {
            'timestamp': time.time()
        }

    @classmethod
    def scanning_status(cls, scan_task):
        """
        Information about scan

        Args:
            scan_task (ScanAsyncTask):

        Returns:
            dict

        """
        return {
            'nodes': [str(node.ip) for node in scan_task.current_scan],
            'networks': cfg.get('service.scans.networks').cfg,
            'ports': cfg.get('service.scans.ports'),
            'previous_scan': scan_task.previous_scan,
            'previous_tool_scan': scan_task.previous_tool_scan,
            'next_scan': scan_task.next_scan,
            'next_tool_scan': scan_task.next_tool_scan,
            'scan_cron': cfg.get('service.scans.scan_cron'),
            'tools_cron': cfg.get('service.scans.tools_cron')
        }

    @classmethod
    def scheduler_task_status(cls, task):
        """
        Returns information about schedulers task

        Args:
            task : named tuple representing scheduler task

        Returns:
            dict

        """
        return {
            'action': task.action.__name__,
            'time': task.time
        }

    @classmethod
    def thread_pool_status(cls, thread_pool):
        """
        Obtain status of thread pool

        Args:
            thread_pool (ThreadPool):

        Returns:
            dict

        """
        return_value = {'queue': [], 'threads': []}

        for thread in thread_pool.threads:
            return_value['threads'].append(cls.thread_pool_thread_status(thread))

        for task in thread_pool.task_queue:
            return_value['queue'].append(cls.task_status(task))

        return_value['threads_limit'] = thread_pool.num_threads

        return return_value

    @classmethod
    def thread_pool_thread_status(cls, thread):
        """
        Returns dict with info about thread

        Args:
            thread(Thread):

        Returns:
            dict

        """
        task = thread.task
        if task is None:
            return {}

        return_value = cls.task_status(thread.task)

        return return_value

    @classmethod
    def task_status(cls, task):
        """
        Returns information about task

        Args:
            task (Task):

        Returns:
            dict

        """
        return_value = {}

        if isinstance(task, Task):
            return_value['start_time'] = task.start_time
            return_value['creation_time'] = task.creation_time
            return_value['name'] = task.name

        if isinstance(task, (Tool, PortTask)):
            return_value['port'] = str(task.port)

        if isinstance(task, Executor):
            return_value['nodes'] = [str(node) for node in task.ports]

        if isinstance(task, PortTask):
            return_value['exploits'] = [exploit.name for exploit in task.current_exploits]

        return return_value
