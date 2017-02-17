"""
Configuration related module

"""
import logging as log

import yaml

from utils.exceptions import ToucanException
from utils.toucan import Toucan


class Config:
    '''
    Creates a configuration using data from YAML file.
    Has ability to provide default values (including dynamic ones)
    Except for loading data, this class is read-only and therefore may be used from multiple threads.
    '''
    def __init__(self, cfg=None):
        if not cfg:
            cfg = {}
        self._cfg = cfg
        self.default = self._cfg.copy()
        self.toucan = None

    def __len__(self):
        return len(self._cfg)

    def __getitem__(self, key):
        ''' Works like "get()" '''
        return self.get(key)

    def __contains__(self, item):
        if isinstance(self._cfg, (list, set)):
            return item in self._cfg
        return False

    def get(self, key):
        """
        Gets data from multilevel dictionary using keys with dots.
        i.e. key="logging.file"
        Raises KeyError if there is no configured value and no default value for the given key.

        """
        try:
            return self._get(key)
        except KeyError:
            log.warning("%s not found in configuration file", key)
            raise KeyError(key)

    def set(self, key, value):
        keys = key.split('.')
        current = self._cfg

        for subkey in keys[:-1]:
            current.setdefault(subkey, {})
            current = current.get(subkey)

        current[keys[-1]] = value

    def __setitem__(self, key, value):
        self.set(key, value)

    def _get(self, key):
        '''
        Gets data from multilevel dictionary using keys with dots.
        i.e. key="logging.file"
        Raises KeyError if there is no configured value and no default value for the given key.

        '''
        keys = key.split('.')

        curr = self._cfg
        for subkey in keys:
            if isinstance(curr, dict):
                curr = curr[subkey]
            elif isinstance(curr, list):
                curr = curr[int(subkey)]
            else:
                raise KeyError(subkey)

        if isinstance(curr, dict) or isinstance(curr, list):
            return Config(curr)
        else:
            return curr

    @property
    def cfg(self):
        '''
        Return list or dict configuration
        '''
        return self._cfg

    def load(self, file_name, defaults=None):
        """
        Loads configuration from provided file name.

        Args:
            file_name(str) - YAML file name with configuration
            defaults(dict) - default values in a form of multilevel dictionary with optional callable objects

        """
        if not defaults:
            defaults = {}

        defaults = self._simplify_defaults(defaults)
        cfg = yaml.load(open(file_name, 'r'))
        self._cfg = self._recursive_merge(cfg, defaults)
        self._cfg['config_filename'] = file_name

    def _recursive_merge(self, data, defaults):
        """
        recursively replace defaults with configured data

        Args:
            data (list|dict): data which should be put into configuration
            defaults (list|dict): default data configuration

        Returns:
            list|dict

        """
        if isinstance(defaults, dict) and isinstance(data, dict):
            output = defaults.copy()
            for key, val in data.items():
                if key in output:
                    output[key] = self._recursive_merge(data[key], output[key])
                else:
                    output[key] = val
            return output
        elif isinstance(data, list) and isinstance(defaults, list):
            common = min(len(data), len(defaults))
            output = [self._recursive_merge(data[i], defaults[i]) for i in range(common)]
            output.extend(data[common:])
            output.extend(defaults[common:])
            return output
        else:
            return data

    def _simplify_defaults(self, defaults):
        if callable(defaults):
            return defaults()
        if isinstance(defaults, dict):
            return {key: self._simplify_defaults(val) for key, val in defaults.items()}
        if isinstance(defaults, list):
            return [self._simplify_defaults(val) for val in defaults]
        return defaults

    def reload(self, file_name):
        """
        Reloads configuration based on file_name

        Args:
            file_name (str): filename

        Returns:
            None

        """
        self.load(file_name, self.default)

    def load_toucan(self, keys):
        self.toucan = Toucan(host=self.get('toucan.api.host'),
                             port=self.get('toucan.api.port'),
                             protocol=self.get('toucan.api.protocol'))

        for key_group in keys:
            for key in key_group:
                try:
                    self[key] = self.toucan.get(key)
                except ToucanException as exception:
                    log.warning("Toucan error: %s", exception)
