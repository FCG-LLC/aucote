from unittest import TestCase
from unittest.mock import patch, MagicMock

from aucote_cfg import load, _DEFAULT


class AucoteCfgTest(TestCase):

    @patch('aucote_cfg.cfg')
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_empty_load(self, cfg_mock):
        load()
        cfg_mock.load.assert_called_once_with('test', _DEFAULT)

    @patch('aucote_cfg.cfg', MagicMock())
    @patch('os.path.join', MagicMock(return_value='test'))
    @patch('aucote_cfg.Config')
    def test_nonexist_file_load(self, mock_cfg):
        mock_cfg.return_value.load.side_effect = FileNotFoundError
        self.assertRaises(SystemExit, load('test'))

    @patch('aucote_cfg.cfg')
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_invalid_file_load(self, mock_cfg):
        mock_cfg.load.side_effect = TypeError
        self.assertRaises(SystemExit, load, 'test')
