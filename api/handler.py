"""
Handler abstract class
"""
import hashlib

from tornado.web import RequestHandler

from aucote_cfg import cfg


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

    @staticmethod
    def auth(handler_class):
        """
        Handler for authorization

        Args:
            handler_class:

        Returns:

        """
        def wrap_execute(handler_execute):
            def require_auth(handler, kwargs):
                auth_header = handler.request.headers.get('Authorization')

                if auth_header is None or not auth_header.startswith('Bearer '):
                    handler.set_status(401)
                    handler._transforms = []
                    handler.finish()
                    return False

                password = auth_header[7:]
                hash = hashlib.sha512(password.encode()).hexdigest()
                correct = cfg.get('service.api.password')

                if hash != correct:
                    handler.set_status(401)
                    handler._transforms = []
                    handler.finish()
                    return False

                return True

            def _execute(self, transforms, *args, **kwargs):
                if not require_auth(self, kwargs):
                    return False
                return handler_execute(self, transforms, *args, **kwargs)

            return _execute

        handler_class._execute = wrap_execute(handler_class._execute)
        return handler_class
