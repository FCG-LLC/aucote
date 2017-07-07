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
        scanners = self._scanners_status()
        unfinished_tasks = self.aucote.task_manager.unfinished_tasks
        stats = {
            'scanners': scanners,
            'unfinished_tasks': unfinished_tasks,
            'meta': self.metadata()
        }
        return stats

    def _scanners_status(self):
        return_value = {}
        for scanner in self.aucote.task_manager.cron_tasks:
            return_value[scanner.NAME] = {
                'current_scan': self._format_nodes(scanner.current_scan),
                'next_scan': scanner.next_scan,
                'previous_scan': scanner.previous_scan,
                'protocol': scanner.PROTOCOL.db_val,
                'scan_start': scanner.scan_start,
                'scan_type': cfg['portdetection.{0}.scan_type'.format(scanner.NAME)],
                'ports': {
                    'included': list(cfg['portdetection.{0}.ports.include'.format(scanner.NAME)]),
                    'excluded': list(cfg['portdetection.{0}.ports.exclude'.format(scanner.NAME)])
                },
                'networks': {
                    'included': list(cfg['portdetection.{0}.networks.include'.format(scanner.NAME)]),
                    'excluded': list(cfg['portdetection.{0}.networks.exclude'.format(scanner.NAME)])
                },
                'cron': scanner.scan_cron,
                'min_time_gap': scanner.scan_interval
            }

        return return_value

    @classmethod
    def _format_nodes(cls, nodes):
        return [str(node) for node in nodes]

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
