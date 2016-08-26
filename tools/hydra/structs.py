class HydraResults(object):

    def __init__(self):
        self._results = []
        self.success = None
        self.all = None

    def __getitem__(self, item):
        return self._results[item]

    def __len__(self):
        return len(self._results)

    def add(self, result):
        if not isinstance(result, HydraResult):
            raise TypeError("Pass {0}, but expected HydraResult.".format(type(result)))
        self._results.append(result)

    def __iter__(self):
        return iter(self._results)

    @property
    def fail(self):
        return self.all - self.success

    def __str__(self):
        return "\n".join([str(result) for result in self._results])


class HydraResult(object):

    def __init__(self, port=None, service=None, host=None, login=None, password=None):
        self.port = port
        self.service = service
        self.host = host
        self.login = login
        self.password = password

    def __str__(self):
        return "login: {2}\tpassword: {3}".format(self.host, self.port, self.login,
                                                                       self.password)
