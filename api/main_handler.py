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
        return {
            'nodes': [str(node.ip) for node in scan_task.current_scan],
            'networks': {
                'include': list(cfg['portdetection.networks.include']),
                'exclude': list(cfg['portdetection.networks.exclude'])
            },
            'ports': {
                'tcp': {
                    'include': list(cfg['portdetection.ports.tcp.include']),
                    'exclude': list(cfg['portdetection.ports.tcp.exclude']),
                },
                'udp': {
                    'include': list(cfg['portdetection.ports.udp.include']),
                    'exclude': list(cfg['portdetection.ports.udp.exclude']),
                },
                'sctp': {
                    'include': list(cfg['portdetection.ports.sctp.include']),
                    'exclude': list(cfg['portdetection.ports.sctp.exclude']),
                },
            },
            'previous_scan': scan_task.previous_scan,
            'previous_tool_scan': scan_task.previous_tool_scan,
            'next_scan': scan_task.next_scan,
            'next_tool_scan': scan_task.next_tool_scan,
            'scan_cron': scan_task._scan_cron(),
            'scan_interval': scan_task._scan_interval(),
            'scan_type': cfg['portdetection.scan_type']
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
