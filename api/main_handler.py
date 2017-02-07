"""
Handler responsible for returns status of aucote

"""
from api.handler import Handler
from aucote_cfg import cfg


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
        stats = self.aucote.thread_pool.stats
        stats['scanner'] = self.scanning_status(self.aucote.scan_thread)
        stats['storage'] = self.storage_status(self.aucote.storage)
        return stats

    def scanning_status(self, scan_thread):
        """
        Information about current scans

        Returns:
            dict

        """
        return {
            'nodes': [str(node.ip) for node in scan_thread.current_scan],
            'scheduler': [self.scheduler_task_status(task) for task in scan_thread.tasks],
            'networks': cfg.get('service.scans.networks').cfg,
            'ports': cfg.get('service.scans.ports'),
            'previous_scan': scan_thread.previous_scan
        }

    @staticmethod
    def scheduler_task_status(task):
        return {
            'action': task.action.__name__,
            'time': task.time
        }

    @staticmethod
    def storage_status(storage):
        """
        Informations about storage status

        Returns:
            dict

        """
        return {
            'path': storage.filename,
        }
