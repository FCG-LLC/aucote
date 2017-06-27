"""
Handler responsible for returning status of aucote

"""
import time

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
        stats = {
            'scanner': self.scanning_status(self.aucote.scan_task),
            'meta': self.metadata()
        }
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
        ports_include = cfg['portdetection.ports.include']
        ports_exlude = cfg['portdetection.ports.exclude']

        return {
            'nodes': [str(node.ip) for node in scan_task.current_scan],
            'networks': {
                'include': list(cfg['portdetection.networks.include']),
                'exclude': list(cfg['portdetection.networks.exclude'])
            },
            'ports': {
                'include': ports_include if isinstance(ports_include, str) else list(ports_include),
                'exclude': ports_exlude if isinstance(ports_exlude, str) else list(ports_exlude),
            },
            'previous_scan': scan_task.previous_scan,
            'previous_tool_scan': scan_task.previous_tool_scan,
            'next_scan': scan_task.next_scan,
            'next_tool_scan': scan_task.next_tool_scan,
            'scan_cron': cfg['portdetection.scan_cron'],
            'tools_cron': cfg['portdetection.tools_cron']
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
