from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from api.main_handler import MainHandler


class UserAPITest(AsyncHTTPTestCase):
    def get_app(self):
        self.aucote = MagicMock()
        self.app = Application([('/', MainHandler, {'aucote': self.aucote})])
        return self.app

    @patch('api.main_handler.json.dumps')
    def test_user_profile_annoymous(self, mock_json):
        mock_json.return_value = "test"
        response = self.fetch('/', method='GET')
        mock_json.assert_called_once_with(self.aucote.get_status.return_value, indent=2)
        self.assertEqual(response.body, b"test")
        self.assertEqual(response.headers['Content-Type'], "application/json")
