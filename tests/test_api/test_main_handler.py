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

    @patch('api.main_handler.MainHandler.aucote_status')
    def test_user_profile_anonymous(self, mock_aucote_status):
        expected = {"test": "test_value"}
        mock_aucote_status.return_value = expected
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 200)
        self.assertEqual(response.headers['Content-Type'], "application/json; charset=UTF-8")
        self.assertEqual(json.loads(response.body.decode()), expected)

    def test_aucote_status(self):
        result = MainHandler(self.app, MagicMock(), aucote=self.aucote).aucote_status()

        expected = self.aucote.thread_pool.stats
        expected['scanner'] = self.aucote.scan_thread.get_info()
        expected['storage'] = self.aucote.storage_thread.get_info()

        self.assertEqual(result, expected)
