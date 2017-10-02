"""
Web server for API

"""
from tornado.httpserver import HTTPServer
from tornado.netutil import bind_sockets
from tornado.web import Application

from api.kill_handler import KillHandler
from api.main_handler import MainHandler
from api.scanners_handler import ScannersHandler
from api.tasks_handler import TasksHandler


class WebServer(object):
    """
    Web server

    """
    def __init__(self, aucote, host, port):
        self.server = None
        self.port = port
        self.host = host
        self.aucote = aucote
        self.name = "WebServer"

    async def run(self):
        """
        Start server

        Returns:
            None

        """
        app = self._make_app()
        sockets = bind_sockets(self.port, address=self.host, reuse_port=True)
        self.server = HTTPServer(app)
        self.server.add_sockets(sockets)

    def stop(self):
        """
        Stop server

        Returns:
            None

        """
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
            (r"/api/v1/scanner/([\w_]+)", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/scanners", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/tasks", TasksHandler, {'aucote': self.aucote}),
        ])
