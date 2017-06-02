class WhatWebPlugin(object):
    """
    Output of WhatWeb single plugin

    """
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', None)
        self.version = kwargs.get('version', None)
        self.os = kwargs.get('os', None)
        self.string = kwargs.get('string', [])
        self.account = kwargs.get('account', None)
        self.model = kwargs.get('model', None)
        self.firmware = kwargs.get('firmware', None)
        self.module = kwargs.get('module', None)
        self.filepath = kwargs.get('filepath', None)

    def __str__(self):
        return "{name}: {plugins}".format(name=self.name, plugins=", ".join(self.string))


class WhatWebTarget(object):
    """
    Result of single WhatWeb output line

    """
    def __init__(self, uri=None, status=None, plugins=None):
        self.uri = uri
        self.status = status
        self.plugins = plugins or []

    def __str__(self):
        return "{address} {status_code}:\n{plugins}".format(address=self.uri, status_code=self.status,
                                                            plugins="\n".join([" - {0}".format(str(plugin))
                                                                               for plugin in self.plugins
                                                                               if plugin.string]))


class WhatWebResult(object):
    """
    Result of WhatWeb execution

    """
    def __init__(self, targets=None):
        self.targets = targets or []

    def __str__(self):
        return "\n----------\n".join(str(target) for target in self.targets)
