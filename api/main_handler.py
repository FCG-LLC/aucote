"""
Handler responsible for returns status of aucote

"""
from api.handler import Handler


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
        stats['scanner'] = self.aucote.scan_thread.get_info()
        stats['storage'] = self.aucote.storage.get_info()
        return stats
