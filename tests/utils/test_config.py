from unittest import TestCase

from utils import Config


class ConfigTest(TestCase):
    '''
    Test config
    '''

    CONFIG = {
        'alice': {
            'has': {
                'a': 'cat',
                'not': [
                    'cat'
                ]
            },
        }
    }

    def setUp(self):
        self.config = Config(cfg = self.CONFIG)

    def test_len(self):
        self.assertEqual(len(self.config), 1)

    def test_empty(self):
        config = Config()
        self.assertEqual(len(config), 0)

    def test_get(self):
        self.assertEqual(self.config.get('alice.has.a'), 'cat')
        self.assertEqual(self.config.get('alice.has.not.0'), 'cat')

        self.assertDictEqual(self.config.get('alice.has')._cfg, self.CONFIG['alice']['has'])

        self.assertRaises(KeyError, self.config.get, 'bob.has.a')