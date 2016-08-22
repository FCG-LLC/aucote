from unittest import TestCase
from unittest.mock import patch, MagicMock
from aucote_cfg import _DEFAULT, load


class ConfigTest(TestCase):

    @patch('os.path.join', MagicMock(return_value='test'))
    @patch('aucote_cfg.cfg.load')
    def test_empty_load(self, cfg_load_mock):
        load()
        cfg_load_mock.assert_called_once_with('test', _DEFAULT)