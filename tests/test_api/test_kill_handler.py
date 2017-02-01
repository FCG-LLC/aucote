from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from api.kill_handler import KillHandler


class UserAPITest(AsyncHTTPTestCase):
    def get_app(self):
        self.aucote = MagicMock()
        self.app = Application([('/', KillHandler, {'aucote': self.aucote})])
        return self.app

    def test_user_profile_annoymous(self):
        self.fetch('/', method='GET')
        self.aucote.kill.assert_called_once_with()
