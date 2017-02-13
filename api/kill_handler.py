"""
Handler responsible for exit aucote application immediately

"""
import hashlib

from api.handler import Handler
from aucote_cfg import cfg

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
