from unittest import TestCase
from unittest.mock import patch, mock_open, MagicMock, call

from tornado.testing import gen_test, AsyncTestCase

from utils import Config
from utils.log import config


class ConfigFileTest(AsyncTestCase):

    @patch('builtins.open', mock_open(read_data=""))
    @patch('utils.log.RotatingFileHandler')
    @patch('utils.log.log')
    @gen_test
    async def test_config(self, mock_log, mock_rotate):
        expected = [MagicMock(), MagicMock()]
        mock_log.getLogger().handlers = expected
        cfg = Config()
        cfg._cfg = {
            'root': {
                'file': 'test_file',
                'max_file_size': 45678,
                'max_files': 13,
                'format': 'TEST format',
                'level': 'info',
                'propagate': True
            }
        }
        await config(cfg)

        self.assertTrue(mock_log.StreamHandler.called)
        self.assertTrue(mock_log.getLogger.called)
        self.assertTrue(mock_log.getLogger.return_value.addHandler.called)

        mock_rotate.assert_called_once_with('test_file', maxBytes=45678, backupCount=13)

        mock_log.Formatter.assert_called_once_with('TEST format')
        mock_log.getLogger().removeHandler.assert_has_calls((call(expected[1]), call(expected[0])))