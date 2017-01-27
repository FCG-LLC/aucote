import json

from api.handler import Handler


class KillHandler(Handler):
    def get(self):
        self.aucote.kill()
