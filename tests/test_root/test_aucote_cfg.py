from unittest import TestCase
from unittest.mock import patch, MagicMock, call, mock_open

from aucote_cfg import load, _DEFAULT, start_toucan
from utils import Config


class AucoteCfgTest(TestCase):
    YAML = '''alice:
    has:
        a: dog'''

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_empty_load(self, cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default',
            'toucan': {
                'enable': False,
            }
        }
        cfg.load = MagicMock()
        cfg.load_toucan = MagicMock()
        load()
        cfg.load.assert_has_calls([call('test', _DEFAULT), call('test_default', cfg._cfg)], False)

    @patch('os.path.join', MagicMock(return_value='test'))
    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    def test_nonexist_file_load(self, mock_cfg):
        mock_cfg.load = MagicMock(side_effect=FileNotFoundError())
        self.assertRaises(SystemExit, load, 'test')

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_invalid_file_load(self, mock_cfg):
        mock_cfg.load = MagicMock(side_effect=TypeError())
        self.assertRaises(SystemExit, load, 'test')

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_invalid_default_file_load(self, cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default',
            'toucan': {
                'enable': False,
            }
        }
        cfg.load = MagicMock(side_effect=(None, TypeError()))
        self.assertRaises(SystemExit, load, 'test')

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('aucote_cfg.start_toucan')
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_toucan_enabled(self, start_toucan, cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default',
            'toucan': {
                'enable': True,
            }
        }

        cfg.load = MagicMock()
        load()
        start_toucan.assert_called_once_with('test_default')

    @patch('builtins.open', mock_open(read_data=YAML))
    @patch('aucote_cfg.Toucan')
    @patch('aucote_cfg.cfg', new_callable=Config)
    def test_load_toucan(self, cfg, toucan):
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
                'max_retry_count': 35
            }
        }

        start_toucan('test_file')
        toucan.return_value.push_config.assert_called_once_with({'alice': {'has': {'a': 'dog'}}}, overwrite=False)
        self.assertEqual(cfg.toucan, toucan.return_value)
        self.assertEqual(toucan.min_retry_time, 15)
        self.assertEqual(toucan.max_retry_count, 35)
        self.assertEqual(toucan.max_retry_time, 25)