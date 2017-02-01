from tornado.web import RequestHandler


class Handler(RequestHandler):
    def initialize(self, aucote):
        self.aucote = aucote
