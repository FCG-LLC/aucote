"""
Web server for API

"""
from threading import Thread

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.netutil import bind_sockets
from tornado.web import Application

from api.kill_handler import KillHandler
from api.main_handler import MainHandler


class WebServerThread(Thread):
    """
    Web server

    """
    def __init__(self, aucote, host, port, *args, **kwargs):
        super(WebServerThread, self).__init__(*args, **kwargs)
        self.server = None
        self.port = port
        self.host = host
        self.aucote = aucote
        self.name = "WebServer"
        self._ioloop = IOLoop()

    def run(self):
        """
        Start server

        Returns:
            None

        """
        self._ioloop = IOLoop.current()
        app = self._make_app()
        sockets = bind_sockets(self.port, address=self.host, reuse_port=True)
        self.server = HTTPServer(app)
        self.server.add_sockets(sockets)
        self._ioloop.start()

    def stop(self):
        """
        Stop server

        Returns:
            None

        """
        self._ioloop.stop()
        if self.server:
            self.server.stop()
            self.server = None

    def _make_app(self):
        """
        Create application

        Returns:
            Application

        """
        return Application([
            (r"/api/v1/status", MainHandler, {'aucote': self.aucote}),
            (r"/api/v1/kill", KillHandler, {'aucote': self.aucote}),
        ])
