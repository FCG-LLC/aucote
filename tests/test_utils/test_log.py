from unittest import TestCase
from unittest.mock import patch, mock_open, MagicMock, call

from utils import Config
from utils.log import config


class ConfigFileTest(TestCase):

    @patch('builtins.open', mock_open(read_data=""))
    @patch('utils.log.RotatingFileHandler')
    @patch('utils.log.log')
    def test_config(self, mock_log, mock_rotate):
        expected = [MagicMock(), MagicMock()]
        mock_log.getLogger().handlers = expected
        cfg = Config()
        cfg._cfg = {
            'file': '',
            'max_file_size': 0,
            'max_files': 0,
            'format': '',
            'level': 'info'
        }
        config(cfg)

        self.assertTrue(mock_log.StreamHandler.called)
        self.assertTrue(mock_log.getLogger.called)
        self.assertTrue(mock_log.getLogger.return_value.addHandler.called)

        mock_rotate.assert_called_once_with(cfg._cfg['file'], maxBytes=cfg._cfg['max_file_size'],
                                            backupCount=cfg._cfg['max_files'])

        mock_log.Formatter.assert_called_once_with(cfg._cfg['format'])
        mock_log.getLogger().removeHandler.assert_has_calls((call(expected[1]), call(expected[0])))