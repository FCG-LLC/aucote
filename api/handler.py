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
        max_password_header_length = 80

        def wrap_execute(handler_execute):
            def require_auth(handler, *args, **kwargs):
                auth_header = handler.request.headers.get('Authorization')

                if len(auth_header) < max_password_header_length and auth_header.startswith('Bearer '):
                    password = auth_header.split('Bearer ')[1]
                    password_hash = hashlib.sha512(password.encode()).hexdigest()
                    correct = cfg.get('service.api.password')

                    if password_hash == correct:
                        return True

                handler.set_status(401)
                handler._transforms = []
                handler.finish()
                return False

            def _execute(self, transforms, *args, **kwargs):
                if not require_auth(self, kwargs):
                    return False
                return handler_execute(self, transforms, *args, **kwargs)

            return _execute

        handler_class._execute = wrap_execute(handler_class._execute)
        return handler_class
