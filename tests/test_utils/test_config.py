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
    }

    YAML = '''alice:
    has:
        a: dog'''

    def setUp(self):
        self.config = Config(cfg = self.CONFIG)

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
        }

    def test_len(self):
        self.assertEqual(len(self.config), 2)

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
        expected = {'alice': {'has': {'a': 'dog'}}, 'config_filename': 'test'}

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
        self.config.load.assert_called_once_with(filename, self.CONFIG)

    def test_contains(self):
        self.assertIn('cat', self.config['alice.has.not'])

    def test_not_contains(self):
        self.assertNotIn('dog', self.config['alice.has.not'])

    def test_not_list(self):
        self.assertNotIn('dog', self.config['alice.has'])

    @patch('builtins.open', mock_open(read_data=YAML))
    @patch('utils.config.Toucan')
    def test_load_toucan(self, toucan):
        self.config._cfg = {
            'toucan': {
                'enable': True,
                'api': {
                    'host': 'localhost',
                    'port': '3000',
                    'protocol': 'http'
                }
            }
        }

        self.config.start_toucan('test_file')
        toucan.return_value.push_config.assert_called_once_with({'alice': {'has': {'a': 'dog'}}}, overwrite=False)
        self.assertEqual(self.config.toucan, toucan.return_value)

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

    def test_get_non_exist_key_with_toucan(self):
        self.config.toucan = MagicMock()
        expected = 'test_value'
        self.config.toucan.get.return_value = expected

        result = self.config['non.exisists.key']

        self.assertEqual(result, expected)
        self.config.toucan.get.assert_called_once_with('non.exisists.key')