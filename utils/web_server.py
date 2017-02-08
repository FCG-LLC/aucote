"""
Web server for API

"""
import socket

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.netutil import bind_sockets
from tornado.web import Application

from api.kill_handler import KillHandler
from api.main_handler import MainHandler


class WebServer(object):
    """
    Web server

    """
    def __init__(self, aucote, host, port):
        self.server = None
        self.port = port
        self.host = host
        self.aucote = aucote

    def start(self):
        """
        Start server

        Returns:
            None

        """
        app = self.make_app()
        sockets = bind_sockets(self.port, address=self.host, reuse_port=True)
        self.server = HTTPServer(app)
        self.server.add_sockets(sockets)
        IOLoop.current().start()

    def stop(self):
        """
        Stop server

        Returns:
            None

        """
        IOLoop.current().stop()
        if self.server:
            self.server.stop()
            self.server = None

    def make_app(self):
        """
        Create application

        Returns:
            Application

        """
        return Application([
            (r"/api/v1/status", MainHandler, {'aucote': self.aucote}),
            (r"/api/v1/kill", KillHandler, {'aucote': self.aucote}),
        ])
