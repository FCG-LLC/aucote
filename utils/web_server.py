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

    async def __aenter__(self):
        await self.run()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.stop()

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
        return Application((url, handler, {'aucote': self.aucote}) for url, handler in [
            (r"/api/v1/kill", KillHandler),
            (r"/api/v1/scanners", ScannersHandler),
            (r"/api/v1/scanners/([\w_]+)", ScannersHandler),
            (r"/api/v1/tasks", TasksHandler),
            (r"/api/v1/scans", ScansHandler),
            (r"/api/v1/scans/([\d]+)", ScansHandler),
            (r"/api/v1/nodes", NodesHandler),
            (r"/api/v1/nodes/([\d]+)", NodesHandler),
            (r"/api/v1/ports", PortsHandler),
            (r"/api/v1/ports/([\d]+)", PortsHandler),
            (r"/api/v1/security_scans", SecurityScansHandler),
            (r"/api/v1/security_scans/([\d]+)", SecurityScansHandler),
            (r"/api/v1/vulnerabilities", VulnerabilitiesHandler),
            (r"/api/v1/vulnerabilities/([\d]+)", VulnerabilitiesHandler),
        ])
