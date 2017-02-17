from unittest import TestCase
from unittest.mock import patch, MagicMock

from aucote_cfg import load, _DEFAULT
from utils import Config


class AucoteCfgTest(TestCase):

    @patch('aucote_cfg.cfg', new_callable=Config)
    @patch('aucote_cfg.log_cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_empty_load(self, cfg):
        cfg._cfg = {
            'logging': ''
        }
        cfg.load = MagicMock()
        cfg.load_toucan = MagicMock()
        load()
        cfg.load.assert_called_once_with('test', _DEFAULT)

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
