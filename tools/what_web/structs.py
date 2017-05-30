class WhatWebPluginOutput(object):
    def __init__(self):
        self.name = None
        self.outputs = []

    def __str__(self):
        return """ - {name}: {plugins}""".format(name=self.name, plugins=", ".join(self.outputs))


class WhatWebResult(object):
    def __init__(self):
        self.address = None
        self.status = None
        self.status_code = None
        self.plugins = []

    def __str__(self):
        return "{address} {status_code}:\n{plugins}".format(address=self.address, status_code=self.status_code,
                                                           plugins="\n".join([str(plugin) for plugin in self.plugins]))


class WhatWebResults(object):
    def __init__(self):
        self.results = []

    def __str__(self):
        return "\n----------\n".join([str(result) for result in self.results])
