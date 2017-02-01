from unittest import TestCase
from unittest.mock import MagicMock

from api.handler import Handler


class HandlerTest(TestCase):
    def setUp(self):
        self.aucote = MagicMock()
        self.handler = Handler(application=MagicMock(), request=MagicMock(), aucote=self.aucote)

    def test_initialize(self):
        self.assertEqual(self.handler.aucote, self.aucote)