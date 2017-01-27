import json

from api.handler import Handler


class MainHandler(Handler):
    def get(self):
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(self.aucote.get_status(), indent=2))
