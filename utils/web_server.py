"""
Web server for API

"""
from tornado.httpserver import HTTPServer
from tornado.netutil import bind_sockets
from tornado.web import Application

from api.kill_handler import KillHandler
from api.nodes_handler import NodesHandler
from api.ports_handler import PortsHandler
from api.scanners_handler import ScannersHandler
from api.scans_handler import ScansHandler
from api.security_scans_handler import SecurityScansHandler
from api.tasks_handler import TasksHandler
from api.vulnerabilitites_handler import VulnerabilitiesHandler


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
            (r"/api/v1/kill", KillHandler, {'aucote': self.aucote}),
            (r"/api/v1/scanners", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/scanners/([\w_]+)", ScannersHandler, {'aucote': self.aucote}),
            (r"/api/v1/tasks", TasksHandler, {'aucote': self.aucote}),
            (r"/api/v1/scans", ScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/scans/([\d]+)", ScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/nodes", NodesHandler, {'aucote': self.aucote}),
            (r"/api/v1/nodes/([\d]+)", NodesHandler, {'aucote': self.aucote}),
            (r"/api/v1/ports", PortsHandler, {'aucote': self.aucote}),
            (r"/api/v1/ports/([\d]+)", PortsHandler, {'aucote': self.aucote}),
            (r"/api/v1/sec_scans", SecurityScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/sec_scans/([\d]+)", SecurityScansHandler, {'aucote': self.aucote}),
            (r"/api/v1/vulnerabilities", VulnerabilitiesHandler, {'aucote': self.aucote}),
            (r"/api/v1/vulnerabilities/([\d]+)", VulnerabilitiesHandler, {'aucote': self.aucote}),
        ])
