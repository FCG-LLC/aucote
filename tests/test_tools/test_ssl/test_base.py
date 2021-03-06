from unittest import TestCase
from unittest.mock import MagicMock, patch

from tools.ssl.base import SSLBase


class SSLBaseTest(TestCase):
    @patch('tools.ssl.base.tempfile.NamedTemporaryFile')
    def setUp(self, mock_file):
        self.mock_file = mock_file
        self.executor = MagicMock()
        self.base = SSLBase()

    def test_init(self):
        self.assertEqual(self.base.COMMON_ARGS, ['--warnings', 'batch', '--jsonfile', self.mock_file.return_value.name,
                                                 '--append'])
        self.assertEqual(self.base.parser.tempfile, self.mock_file.return_value)

    @patch('tools.ssl.base.tempfile.NamedTemporaryFile')
    def test_double_init(self, mock_file):
        self.base = SSLBase()
        self.assertEqual(self.base.COMMON_ARGS, ['--warnings', 'batch', '--jsonfile', mock_file.return_value.name,
                                                 '--append'])
        self.assertEqual(self.base.parser.tempfile, mock_file.return_value)
