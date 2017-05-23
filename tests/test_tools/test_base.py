from unittest import TestCase
from unittest.mock import MagicMock

from tools.base import Tool


class ToolTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.aucote.storage.filename = ":memory:"
        self.exploits = MagicMock()
        self.config = MagicMock()
        self.port = MagicMock()

        self.tool = Tool(aucote=self.aucote, exploits=self.exploits, port=self.port, config=self.config)

    def test_init(self):
        self.assertEqual(self.tool.aucote, self.aucote)
        self.assertEqual(self.tool.exploits, self.exploits)
        self.assertEqual(self.tool.config, self.config)
        self.assertEqual(self.tool.port, self.port)

    def test_call(self):
        self.assertRaises(NotImplementedError, self.tool)
