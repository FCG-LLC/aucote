class MultilevelStruct(object):
    def __init__(self, initialize=None):
        self._struct = initialize or {}

    def __getitem__(self, item):
        try:
            return self._get(item)
        except KeyError:
            raise KeyError(item)

    def get(self, item, default=None):
        try:
            return self._get(item)
        except KeyError:
            return default

    def _get(self, key):
        keys = key.split('.')
        curr = self._struct

        for k in keys:
            if isinstance(curr, dict):
                curr = curr[k]
            elif isinstance(curr, list):
                curr = curr[int(k)]
            else:
                raise KeyError(k)

        if isinstance(curr, (dict, list, set)):
            return MultilevelStruct(curr)
        else:
            return curr

    def __setitem__(self, key, value):
        keys = key.split('.')
        curr = self._struct

        for k in keys[:-1]:
            if isinstance(curr, dict):
                curr = curr[k]
            elif isinstance(curr, list):
                curr = curr[int(k)]
            else:
                raise KeyError(k)

        k = keys[-1]

        if isinstance(curr, dict):
            curr[k] = value
        elif isinstance(curr, list):
            curr[int(k)] = value
        else:
            raise KeyError(k)

        return self[key]

    def __contains__(self, item):
        return item in self._struct