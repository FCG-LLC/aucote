from unittest import TestCase
from unittest.mock import patch, MagicMock, call, mock_open

from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from aucote_cfg import load, _DEFAULT, start_toucan
from utils import Config


class AucoteCfgTest(AsyncTestCase):
    YAML = '''alice:
    has:
        a: dog'''

    @patch('aucote_cfg.log_cfg')
    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('os.path.join', MagicMock(return_value='test'))
    @gen_test
    async def test_empty_load(self, cfg, log_cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default',
            'toucan': {
                'enable': False,
            }
        }
        log_cfg.config.return_value = Future()
        log_cfg.config.return_value.set_result(MagicMock())

        cfg.load = MagicMock()
        cfg.load_toucan = MagicMock()
        await load()
        cfg.load.assert_has_calls([call('test', _DEFAULT), call('test_default', cfg._cfg)], False)

    @patch('os.path.join', MagicMock(return_value='test'))
    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @gen_test
    async def test_nonexist_file_load(self, mock_cfg):
        mock_cfg.load = MagicMock(side_effect=FileNotFoundError())
        with self.assertRaises(SystemExit):
            await load('test')

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    @gen_test
    async def test_invalid_file_load(self, mock_cfg):
        mock_cfg.load = MagicMock(side_effect=TypeError())
        with self.assertRaises(SystemExit):
            await load('test')

    @patch('aucote_cfg.log_cfg')
    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('os.path.join', MagicMock(return_value='test'))
    @gen_test
    async def test_invalid_default_file_load(self, cfg, log_cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default',
            'toucan': {
                'enable': False,
            }
        }

        log_cfg.config.return_value = Future()
        log_cfg.config.return_value.set_result(MagicMock())

        cfg.load = MagicMock(side_effect=(None, TypeError()))
        with self.assertRaises(SystemExit):
            await load('test')

    @patch('aucote_cfg.log_cfg')
    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.start_toucan')
    @patch('os.path.join', MagicMock(return_value='test'))
    @gen_test
    async def test_toucan_enabled(self, start_toucan, cfg, log_cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default',
            'toucan': {
                'enable': True,
            }
        }

        log_cfg.config.return_value = Future()
        log_cfg.config.return_value.set_result(MagicMock())

        start_toucan.return_value = Future()
        start_toucan.return_value.set_result(MagicMock())

        cfg.load = MagicMock()
        await load()
        start_toucan.assert_called_once_with('test_default')

    @patch('builtins.open', mock_open(read_data=YAML))
    @patch('aucote_cfg.Toucan')
    @patch('aucote_cfg.cfg', new_callable=Config)
    @gen_test
    async def test_load_toucan(self, cfg, toucan):
        cfg._cfg = {
            'toucan': {
                'enable': True,
                'api': {
                    'host': 'localhost',
                    'port': '3000',
                    'protocol': 'http'
                },
                'min_retry_time': 15,
                'max_retry_time': 25,
                'max_retry_count': 35,
                'overwrite': False,
                'push_default': True
            },
            'rabbit': {
                'enable': False,
                'host': 'localhost',
                'port': 5672,
                'username': 'test_user',
                'password': 'some_pass'
            }
        }

        toucan().async_push_config.return_value = Future()
        toucan().async_push_config.return_value.set_result(MagicMock())

        toucan().async_get.return_value = Future()
        toucan().async_get.return_value.set_result(MagicMock())

        await start_toucan('test_file')
        toucan.return_value.async_push_config.assert_called_once_with({'alice': {'has': {'a': 'dog'}}}, overwrite=False)
        self.assertEqual(cfg.toucan, toucan.return_value)
        self.assertEqual(toucan.min_retry_time, 15)
        self.assertEqual(toucan.max_retry_count, 35)
        self.assertEqual(toucan.max_retry_time, 25)

    @patch('builtins.open', mock_open(read_data=YAML))
    @patch('aucote_cfg.Toucan')
    @patch('aucote_cfg.cfg', new_callable=Config)
    @gen_test
    async def test_load_toucan_with_overwrite(self, cfg, toucan):
        cfg._cfg = {
            'toucan': {
                'enable': True,
                'api': {
                    'host': 'localhost',
                    'port': '3000',
                    'protocol': 'http'
                },
                'min_retry_time': 15,
                'max_retry_time': 25,
                'max_retry_count': 35,
                'overwrite': True,
                'push_default': True
            },
            'rabbit': {
                'enable': False,
                'host': 'localhost',
                'port': 5672,
                'username': 'test_user',
                'password': 'some_pass'
            }
        }

        toucan().async_push_config.return_value = Future()
        toucan().async_push_config.return_value.set_result(MagicMock())

        toucan().async_get.return_value = Future()
        toucan().async_get.return_value.set_result(MagicMock())

        await start_toucan('test_file')
        toucan.return_value.async_push_config.assert_called_once_with({'alice': {'has': {'a': 'dog'}}}, overwrite=True)
