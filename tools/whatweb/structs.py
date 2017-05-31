class WhatWebPlugin(object):
    """
    Output of WhatWeb single plugin

    """
    def __init__(self):
        self.name = None
        self.version = None
        self.os = None
        self.string = []
        self.account = None
        self.model = None
        self.firmware = None
        self.module = None
        self.filepath = None

    def __str__(self):
        return """ - {name}: {plugins}""".format(name=self.name, plugins=", ".join(self.string))


class WhatWebTarget(object):
    """
    Result of single WhatWeb output line

    """
    def __init__(self):
        self.uri = None
        self.status = None
        self.plugins = []

    def __str__(self):
        return "{address} {status_code}:\n{plugins}".format(address=self.uri, status_code=self.status,
                                                            plugins="\n".join([str(plugin) for plugin in self.plugins]))


class WhatWebResult(object):
    """
    Result of WhatWeb execution

    """
    def __init__(self):
        self.targets = []

    def __str__(self):
        return "\n----------\n".join([str(target) for target in self.targets])
