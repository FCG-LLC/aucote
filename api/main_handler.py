"""
Handler responsible for returns status of aucote

"""
import json

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
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(self.aucote.get_status(), indent=2))
