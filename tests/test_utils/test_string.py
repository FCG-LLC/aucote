from unittest import TestCase

from utils.string import safe_str, bytes_str, iterable_str


class StringTest(TestCase):

    def test_safe_str(self):
        self.assertEqual(safe_str(10), '10')
        self.assertEqual(safe_str(None), None)

    def test_bytes_str(self):
        self.assertEqual(bytes_str(bytes('abc', 'ascii')), '616263')

    def test_iterable_str(self):
        self.assertEqual(iterable_str(['a', 'b', 'c']), 'a, b, c')
