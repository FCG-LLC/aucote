from unittest.mock import MagicMock, patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from api.kill_handler import KillHandler
from utils import Config


class UserAPITest(AsyncHTTPTestCase):
    def get_app(self):
        self.aucote = MagicMock()
        self.app = Application([('/', KillHandler, {'aucote': self.aucote})])
        return self.app

    @patch('api.kill_handler.cfg', new_callable=Config)
    def test_user_profile_annoymous(self, cfg):
        cfg._cfg = {
            'service': {
                'api': {
                    'password': 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc'
                                '887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
                }
            }
        }
        self.fetch('/', method='POST', body='password=test')
        self.aucote.kill.assert_called_once_with()

    def test_no_password(self):
        result = self.fetch('/', method='POST', body='')
        self.assertFalse(self.aucote.kill.called)
        self.assertEqual(result.code, 403)

    @patch('api.kill_handler.cfg', new_callable=Config)
    def test_bad_password(self, cfg):
        cfg._cfg = {
            'service': {
                'api': {
                    'password': 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc'
                                '887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
                }
            }
        }
        result = self.fetch('/', method='POST', body='password=abs')
        self.assertFalse(self.aucote.kill.called)
        self.assertEqual(result.code, 403)
