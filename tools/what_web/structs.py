class WhatWebPluginOutput(object):
    def __init__(self):
        self.name = None
        self.outputs = []


class WhatWebResult(object):
    def __init__(self):
        self.address = None
        self.status = None
        self.status_code = None
        self.plugins = []


class WhatWebResults(object):
    def __init__(self):
        self.results = []
