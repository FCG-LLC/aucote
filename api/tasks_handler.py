"""
Handler responsible for returning aucote's tasks

"""
from api.handler import Handler


class TasksHandler(Handler):
    def get(self, scan=None):
        task_manager = self.aucote.async_task_manager
        queue_tasks = task_manager._tasks._queue
        workers = task_manager._task_workers

        self.write({
            'unfinished_tasks': self.aucote.unfinished_tasks,
            'queue': [str(task) for task in queue_tasks],
            'workers': {
                'count': len(workers),
                'jobs': {number: str(worker) if worker is not None else None for number, worker in workers.items()},
            }
        })
