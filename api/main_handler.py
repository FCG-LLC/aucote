"""
Handler responsible for returns status of aucote

"""
from api.handler import Handler
from aucote_cfg import cfg
import time
import logging as log

from scans.executor import Executor
from tools.base import Tool
from tools.common.port_task import PortTask


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
        stats['scanner'] = self.scanning_status(self.aucote.scan_thread)
        stats['storage'] = self.storage_status(self.aucote.storage)
        return stats

    @classmethod
    def scanning_status(cls, scan_thread):
        """
        Information about current scans

        Returns:
            dict

        """
        return {
            'nodes': [str(node.ip) for node in scan_thread.current_scan],
            'scheduler': [cls.scheduler_task_status(task) for task in scan_thread.tasks],
            'networks': cfg.get('service.scans.networks').cfg,
            'ports': cfg.get('service.scans.ports'),
            'previous_scan': scan_thread.previous_scan
        }

    @classmethod
    def scheduler_task_status(cls, task):
        return {
            'action': task.action.__name__,
            'time': task.time
        }

    @classmethod
    def storage_status(cls, storage):
        """
        Informations about storage status

        Returns:
            dict

        """
        return {
            'path': storage.filename,
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
            if thread.task is None:
                continue
            return_value['threads'].append(cls.thread_pool_thread_status(thread))

        for task in thread_pool.task_queue:
            return_value['queue'].append(cls.task_status(task))

        return_value['queue_length'] = len(return_value['queue'])
        return_value['threads_length'] = len(return_value['threads'])
        return_value['threads_limit'] = thread_pool.num_threads

        return return_value

    @classmethod
    def task_status(cls, task):
        """
        Returns informations about task

        Args:
            task:

        Returns:
            dict
        """
        return {
            'type': type(task).__name__,
            'data': cls.detailed_task_status(task),
        }

    @classmethod
    def thread_pool_thread_status(cls, thread):
        """
        Returns dict with info about thread

        Args:
            thread:

        Returns:
            dict
        """
        return_value = cls.task_status(thread.task)
        return_value['start_time'] = thread.start_time
        return_value['duration'] = time.time() - thread.start_time

        return return_value

    @classmethod
    def detailed_task_status(cls, task):
        return_value = {}

        if isinstance(task, (Tool, PortTask)):
            return_value['port'] = str(task.port)

        if isinstance(task, Executor):
            return_value['nodes'] = [str(node) for node in task.ports]

        if isinstance(task, PortTask):
            return_value['lifetime'] = time.time() - task.creation_time
            return_value['exploits'] = [exploit.name for exploit in task.current_exploits]

        return return_value
