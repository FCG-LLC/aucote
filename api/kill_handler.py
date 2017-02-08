"""
Handler responsible for exit aucote application immediately

"""
import hashlib

from api.handler import Handler
from aucote_cfg import cfg


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
        password = self.get_argument('password', None)
        if password is None or hashlib.sha512(password.encode()).hexdigest() != cfg.get('service.api.password'):
            self.set_status(403)
            return

        self.aucote.kill()
