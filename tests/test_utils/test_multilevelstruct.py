from unittest import TestCase

from utils.multilevelstruct import MultilevelStruct


class MultilevelStructTest(TestCase):

    def setUp(self):
        self.data = {
            'key_str': 'key_str',
            5: 'key_int',
            '5': 'key_str_int',
            'list': [
                'el1',
                'el2',
                'el3',
                'el4',
                'el5'
            ],
            'multi': {
                'level': {
                    'key': 'test_multi'
                }
            }
        }

        self.struct = MultilevelStruct(self.data)

    def test_init(self):
        self.assertEqual(self.struct._struct, self.data)

    def test_get(self):
        result = self.struct['multi.level.key']
        expected = 'test_multi'

        self.assertEqual(result, expected)

    def test_set(self):
        expected = 'test_exist'
        self.struct['multi.level.key'] = expected

        result = self.struct._struct['multi']['level']['key']

        self.assertEqual(result, expected)

    def test_contains(self):
        expected = 'el5'

        self.assertIn(expected, self.struct['list'])
