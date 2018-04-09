from unittest import TestCase
from unittest.mock import patch, mock_open, MagicMock, call

from tornado.testing import gen_test, AsyncTestCase

from utils import Config
from utils.log import config


class ConfigFileTest(AsyncTestCase):

    @patch('builtins.open', mock_open(read_data=""))
    @patch('utils.log.setup_logger')
    @patch('utils.log.log')
    @gen_test
    async def test_config(self, mock_log, setup_logger):
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

        setup_logger.assert_has_calls((
            call(filename='test_file', level='info', log_format='TEST format', max_file_size=45678, max_files=13,
                 name=None, propagate=True),
            call(filename='test_file.WARNING', level='warning', log_format='TEST format', max_file_size=45678,
                 max_files=13, name=None, propagate=True, fresh=False, stderr=False)))
