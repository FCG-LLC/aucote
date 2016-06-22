import yaml

class Config:
    '''
    Creates a configuration using data from YAML file.
    Has ability to provide default values (including dynamic ones)

    Except for loading data, this class is read-only and therefore may be used from multiple threads.
    '''
    def __init__(self, default=None):
        '''
        Args:
            default(dict) - structure with default values. Values may be both constand or callable (used in dynamic manner)
        '''
        self._cfg = {}
        self._default = default if default else {}

    def get(self, key):
        '''
        Gets data from multilevel dictionary using keys with dots.
        i.e. key="logging.file"

        Raises KeyError if there is no configured value and no default value for the given key.
        '''

        keys = key.split('.')
        try:
            val = self._dict_get(keys, self._cfg)
            return val
        except KeyError:
            pass

        val = self._dict_get(keys, self._default)
        return val() if callable(val) else val

    def load(self, file_name):
        '''
        Loads configuration from provided file name.
        Needs to be called before other functions are used.
        '''
        with open(file_name, 'r') as stream:
            self._cfg = yaml.load(stream.read())
            if self._cfg is None:
                self._cfg = {}

    def _dict_get(self, keys, d):
        curr = d
        for key in keys:
            #can raise KeyError
            curr = curr[key]
        return curr