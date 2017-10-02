"""
Handler responsible for returning status of aucote

"""
import time

from api.handler import Handler
from aucote_cfg import cfg
from scans.tools_scanner import ToolsScanner


class TasksHandler(Handler):
    """
    Handler responsible for returning status of aucote

    """
    def get(self, scan=None):
        """
        Handle get method and returns aucote status in JSON

        Returns:
            None - writes aucote status in JSON

        """
        task_manager = self.aucote.async_task_manager
        queue_tasks = task_manager._tasks._queue
        workers = task_manager._task_workers

        self.write({
            'unfinished_tasks': self.aucote.unfinished_tasks,
            'queue': [str(task) for task in queue_tasks],
            'workers': {
                'count': len(workers),
                'jobs': [str(item) for item in workers if item is not None],
            }
        })