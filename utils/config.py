"""
Configuration related module

"""
import logging as log

import time
from threading import Lock

import yaml

from utils.toucan import Toucan

class Config:
    '''
    Creates a configuration using data from YAML file.
    Has ability to provide default values (including dynamic ones)
    Except for loading data, this class is read-only and therefore may be used from multiple threads.
    '''

    def __init__(self, cfg=None):
        self._lock = Lock()
        self.timestamps = {}
        self._cfg = {}
        self._immutable = set()
        self.push_config(cfg or {}, immutable=True)
        self.default = self._cfg.copy()
        self.toucan = None
        self.cache_time = 60*5

    def __len__(self):
        return len(self._cfg)

    def __getitem__(self, key):
        ''' Works like "get()" '''
        if isinstance(self._cfg, list):
            return self._cfg[key]
        return self.get(key)

    def __contains__(self, item):
        if isinstance(self._cfg, (list, set)):
            return item in self._cfg
        return False

    def get(self, key):
        """
        Get configuration value basing on key.

        First, try to return immutable config (e.g. pid or logging).
        Later returns cached config and if non-exists or config is too old update it from Toucan if enable.

        Args:
            key (str):

        Returns:
            mixed

        """
        try:
            if key in self._immutable:
                return_value = self._get(key)
            elif self.toucan:
                if key in self.timestamps and self.timestamps[key] + self.cache_time > time.time():
                    return_value = self._get(key)
                elif self.toucan.is_special(key):
                    return_value = self.toucan.get(key, False)
                    for subkey, value in return_value:
                        self[subkey] = value
                    return_value = self._get(key)
                else:
                    return_value = self.toucan.get(key)
                    self[key] = return_value
            else:
                return_value = self._get(key)

            if isinstance(return_value, dict) or isinstance(return_value, list):
                return Config(return_value)
            else:
                return return_value
        except KeyError:
            raise KeyError(key)

    def set(self, key, value):
        """
        Set config

        Args:
            key(str):
            value(mixed):

        Returns:
            None

        """
        with self._lock:
            self.timestamps[key] = time.time()
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

        with self._lock:
            curr = self._cfg
            for subkey in keys:
                if isinstance(curr, dict):
                    curr = curr[subkey]
                elif isinstance(curr, list):
                    curr = curr[int(subkey)]
                else:
                    raise KeyError(subkey)

            return curr

    @property
    def cfg(self):
        '''
        Return list or dict configuration
        '''
        return self._cfg

    def load(self, file_name, defaults=None, immutable=True):
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
        self.push_config(self._recursive_merge(cfg, defaults), immutable=immutable)
        self['config_filename'] = file_name

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

    def start_toucan(self, default_config):
        """
        Initialize Toucan

        Args:
            default_config:

        Returns:
            None

        """
        self.toucan = Toucan(host=self['toucan.api.host'],
                             port=self['toucan.api.port'],
                             protocol=self['toucan.api.protocol'])

        with open(default_config, "r") as f:
            config = yaml.load(f)

        self.toucan.push_config(config, overwrite=False)

    def push_config(self, config, key='', immutable=True):
        """
        Merge config(dict) with current config. Resfresh timestamps and set immutable if needed

        Args:
            config(dict):
            key(str): base key
            immutable(bool): determine if config should be immutable for Toucan

        Returns:
            None

        """
        if not isinstance(config, dict):
            self._cfg = config
            return

        for subkey, value in config.items():
            if key:
                new_key = '.'.join([key, subkey])
            else:
                new_key = subkey

            if isinstance(value, dict):
                self.push_config(value, new_key, immutable)
                continue

            self[new_key] = value

            if immutable:
                self._immutable.update({new_key})
