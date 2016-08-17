import unittest
from unittest.mock import MagicMock

from utils.database_interface import DbInterface


class DbInterfaceTest(unittest.TestCase):
    def setUp(self):
        self.db = DbInterface()

    def test_context_manager(self):
        self.db.connect = MagicMock()
        self.db.close = MagicMock()
        with self.db as _:
            pass

        self.db.connect.assert_called_once_with()
        self.db.close.assert_called_once_with()

    def test_interface(self):
        self.assertRaises(NotImplementedError, self.db.connect)
        self.assertRaises(NotImplementedError, self.db.close)

