from unittest import TestCase
from unittest.mock import patch, MagicMock

from aucote_cfg import load, _DEFAULT


class AucoteCfgTest(TestCase):

    @patch('aucote_cfg.cfg')
    @patch('os.path.join', MagicMock(return_value='test'))
    def test_empty_load(self, cfg_mock):
        load()
        cfg_mock.load.assert_called_once_with('test', _DEFAULT)