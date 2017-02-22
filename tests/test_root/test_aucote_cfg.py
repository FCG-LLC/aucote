from unittest import TestCase
from unittest.mock import patch, MagicMock, call

from aucote_cfg import load, _DEFAULT
from utils import Config


class AucoteCfgTest(TestCase):

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_empty_load(self, cfg):
        cfg._cfg = {
            'logging': '',
            'default_config': 'test_default'
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
            'default_config': 'test_default'
        }
        cfg.load = MagicMock(side_effect=(None, TypeError()))
        self.assertRaises(SystemExit, load, 'test')
