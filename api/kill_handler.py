"""
Handler responsible for exit aucote application immediately

"""
from api.handler import Handler


class KillHandler(Handler):
    """
    Kills aucote

    """
    def get(self):
        """
        Kills aucote

        Returns:
            None - kill application
        """
        self.aucote.kill()
