import socket

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.kill_handler import KillHandler
from api.main_handler import MainHandler


class WebServer(object):
    def __init__(self, aucote, host, port):
        self.server = None
        self.port = port
        self.host = host
        self.aucote = aucote

    def start(self):
        app = self.make_app()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(0)
        sock.bind((self.host, self.port))
        sock.listen(1)

        self.server = HTTPServer(app)
        self.server.add_socket(sock)

        IOLoop.instance().start()

    def stop(self):
        IOLoop.current().stop()
        if self.server:
            self.server.stop()
            self.server = None

    def make_app(self):
        return Application([
            (r"/api/v1/status", MainHandler, {'aucote': self.aucote}),
            (r"/api/v1/kill", KillHandler, {'aucote': self.aucote}),
        ])