import json
from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.main_handler import MainHandler


class UserAPITest(AsyncHTTPTestCase):
    def get_app(self):
        self.aucote = MagicMock()
        self.app = Application([('/', MainHandler, {'aucote': self.aucote})])
        return self.app

    def test_user_profile_anonymous(self):
        expected = {"test": "test_value"}
        self.aucote.get_status.return_value = expected
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)
