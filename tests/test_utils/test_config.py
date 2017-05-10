from unittest import TestCase
from unittest.mock import MagicMock, patch, mock_open, call

from utils import Config
from utils.exceptions import ToucanException


class ConfigTest(TestCase):
    """
    Test config
    """

    CONFIG = {
        'alice': {
            'has': {
                'a': 'cat',
                'not': [
                    'cat'
                ]
            },
        },
        'config_filename': 'test',
        'empty_dict': {}
    }

    YAML = '''alice:
    has:
        a: dog'''

    def setUp(self):

        self.CONFIG = {
            'alice': {
                'has': {
                    'a': 'cat',
                    'not': [
                        'cat'
                    ]
                },
            },
            'config_filename': 'test',
            'empty_dict': {}
        }
        self.config = Config(cfg=self.CONFIG)

    def test_len(self):
        self.assertEqual(len(self.config), 3)

    def test_empty_dict(self):
        self.assertEqual(self.config._cfg['empty_dict'], {})

    def test_empty_config_len(self):
        config = Config()
        self.assertEqual(len(config), 0)

    def test_simplify_defaults_callable(self):
        callable_dafaults = MagicMock()
        self.config._simplify_defaults(callable_dafaults)

        callable_dafaults.assert_called_once_with()

    def test_simplify_dict(self):
        dict_defaults = {'test': {'test2': 'nothing'}}
        self.assertDictEqual(self.config._simplify_defaults(dict_defaults), dict_defaults)

    def test_simplify_list(self):
        list_defaults = ['test', 'test2']
        self.assertListEqual(self.config._simplify_defaults(list_defaults), list_defaults)

    def test_recursive_merge_neither_dict_nor_list(self):
        data = 'config'
        result = self.config._recursive_merge(data, self.CONFIG)

        self.assertEqual(result, data)

    def test_recursive_merge_lists(self):
        defaults = [{'test1': 'test'}, {'test2':'test2'}]
        data = [{'test1': 'test3'}]
        expected = [{'test1': 'test3'}, {'test2':'test2'}]

        result = self.config._recursive_merge(data, defaults)
        self.assertListEqual(result, expected)

    def test_recursive_merge_dicts(self):
        defaults = {'test1': 'test1', 'test2': 'test2'}
        data = {'test1': 'test3', 'test4': 'test'}
        expected = {'test1': 'test3', 'test2': 'test2', 'test4': 'test'}

        result = self.config._recursive_merge(data, defaults)
        self.assertDictEqual(result, expected)

    def test_recursive_merge_dicts_with_adding_value(self):
        defaults = {'test1': [{'test1': 'test'}, {'test2':'test2'}], 'test2': 'test2'}
        data = {'test1': [{'test1': 'test3', 'test4': 'test'}]}
        expected = {'test1': [{'test1': 'test3', 'test4': 'test'}, {'test2':'test2'}], 'test2': 'test2'}

        result = self.config._recursive_merge(data, defaults)
        self.assertDictEqual(result, expected)

    @patch('builtins.open', mock_open(read_data=YAML))
    def test_load_yaml(self):
        expected = self.CONFIG.copy()
        expected['alice']['has']['a'] = 'dog'

        self.config.load('test', self.CONFIG)

        result = self.config.cfg

        self.assertDictEqual(result, expected)

    @patch('builtins.open', mock_open(read_data=YAML))
    def test_load_yaml_without_defaults(self):
        expected = {'alice': {'has': {'not': ['cat'], 'a': 'dog'}}, 'config_filename': 'test', 'empty_dict': {}}

        self.config.load('test')

        result = self.config.cfg

        self.assertDictEqual(result, expected)

    def test_get(self):
        expected = 'cat'
        result = self.config.get('alice.has.a')

        self.assertEqual(result, expected)

        self.assertEqual(self.config.get('alice.has.a'), 'cat')
        self.assertEqual(self.config.get('alice.has.not.0'), 'cat')
        self.assertDictEqual(self.config.get('alice.has')._cfg, self.CONFIG['alice']['has'])
        self.assertRaises(KeyError, self.config.get, 'alice.has.a.cat.named.kitty')

    def test_get_toucan_exception(self):
        self.config.toucan = MagicMock()
        self.config.toucan.get = MagicMock(side_effect=ToucanException)
        self.assertRaises(KeyError, self.config.get, 'alice.has.a.cat.named.kitty')

    def test_get_non_exist(self):
        self.assertRaises(KeyError, self.config.get, 'this.not.exist')

    def test_magic_get(self):
        expected = 'cat'
        result = self.config['alice.has.a']

        self.assertEqual(result, expected)

    def test_reload(self):
        self.config.load = MagicMock()
        filename = 'test_filename'
        self.config.reload(filename)
        self.config.load.assert_called_once_with(filename, self.CONFIG)

    def test_reload_after_change_cfg(self):
        self.config.load = MagicMock()
        self.config._cfg['alice'] = None
        filename = 'test_filename'
        self.config.reload(filename)
        cfg =  {
            'alice': {
                'has': {
                    'a': 'cat',
                    'not': [
                        'cat'
                    ]
                },
            },
            'config_filename': 'test',
            'empty_dict': {}
        }
        self.config.load.assert_called_once_with(filename, cfg)

    def test_contains(self):
        self.assertIn('cat', self.config['alice.has.not'])

    def test_not_contains(self):
        self.assertNotIn('dog', self.config['alice.has.not'])

    def test_not_list(self):
        self.assertNotIn('dog', self.config['alice.has'])

    def test_set(self):
        expected = MagicMock()
        self.config['test.adding.key'] = expected
        result = self.config._cfg.get('test', {}).get('adding', {}).get('key', None)

        self.assertEqual(result, expected)

    def test_set_exist_key(self):
        self.config._cfg = {
            'test': {
                'adding': {
                    'key': 'exist_key'
                }
            }
        }
        expected = MagicMock()
        self.config['test.adding.key'] = expected
        result = self.config._cfg.get('test', {}).get('adding', {}).get('key', None)

        self.assertEqual(result, expected)

    @patch('utils.config.time.time', MagicMock(return_value=20))
    def test_get_non_exist_key_with_toucan(self):
        self.config.toucan = MagicMock()
        self.config.toucan.is_special.return_value = False
        self.cache_time = 1
        expected = 'test_value'
        self.config.toucan.get.return_value = expected

        result = self.config['non.exisists.key']

        self.assertEqual(result, expected)
        self.config.toucan.get.assert_called_once_with('non.exisists.key')

    @patch('utils.config.time.time', MagicMock(return_value=20))
    def test_get_cached_config_with_toucan(self):
        self.config.toucan = MagicMock()
        self.config.timestamps = {
            'alice.has.a': 15,
        }
        self.config._immutable = {}
        self.config.cache_time = 10
        expected = 'cat'
        self.assertFalse(self.config.toucan.get.called)

        result = self.config['alice.has.a']
        self.assertEqual(result, expected)

    @patch('utils.config.time.time')
    def test_get_strict_config_with_toucan(self, mock_time):
        self.config.toucan = MagicMock()
        self.config.timestamps = {
            'alice.has.a': 15,
        }
        self.config._immutable = {'alice.has.a'}
        self.config.cache_time = 10
        expected = 'cat'
        result = self.config['alice.has.a']

        self.assertFalse(self.config.toucan.get.called)

        self.assertEqual(result, expected)

    @patch('utils.config.time.time', MagicMock(return_value=50))
    def test_get_special_config_with_toucan(self):
        self.config.toucan = MagicMock()
        self.config.toucan.is_special.return_value = True
        self.config.toucan.get.return_value = {'alice.has.a': 'cat', 'test.key': 'test_value'}
        self.config.timestamps = {
            'alice.has.a': 15,
        }
        self.config.cache_time = 10
        expected = 'cat'

        result = self.config['alice.has.a']
        self.assertEqual(result, expected)
        self.assertEqual(self.config['test.key'], 'test_value')
        self.assertEqual(self.config.timestamps['alice.has.a'], 50)
        self.assertEqual(self.config.timestamps['test.key'], 50)

    def test_multtiple_key(self):
        result = self.config._get('alice.*')
        expected = {
            'has': {
                'a': 'cat',
                'not': [
                    'cat'
                ]
            }
        }

        self.assertEqual(result, expected)
