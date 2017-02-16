"""
Handler responsible for exit aucote application immediately

"""

from api.handler import Handler

@Handler.auth
class KillHandler(Handler):
    """
    Kills aucote

    """
    def post(self):
        """
        Kills aucote. Require password POST argument

        Returns:
            None - kill application

        """

        self.aucote.kill()
