"""
Handler abstract class
"""
from tornado.web import RequestHandler


class Handler(RequestHandler):
    """
    Defines common properties for handler

    """
    def initialize(self, aucote):
        """
        Integrates Handlers with aucote

        Args:
            aucote (Aucote):

        Returns:
            None

        """
        self.aucote = aucote
