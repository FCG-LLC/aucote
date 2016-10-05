"""
This module provides structs used by Hydra task and tool

"""


class HydraResults(object):
    """
    Collection of Hydra Results

    """
    def __init__(self):
        """
        Init values

        """
        self._results = []
        self.success = None
        self.all = None

    def __getitem__(self, item):
        """
        This function allow to use objects as collection

        Args:
            item:

        Returns:
            HydraResult

        """
        return self._results[item]

    def __len__(self):
        """
        Size of collection

        Returns:
            int

        """
        return len(self._results)

    def add(self, result):
        """
        Adds result to the collection

        Args:
            result (HydraResult):

        Returns:
            None

        """
        if not isinstance(result, HydraResult):
            raise TypeError("Pass {0}, but expected HydraResult.".format(type(result)))
        self._results.append(result)

    def __iter__(self):
        """
        Allows to iterating over collection elements

        Returns:
            HydraResult

        """
        return iter(self._results)

    @property
    def fail(self):
        """
        Amount of failed scans

        Returns:
            int

        """
        return self.all - self.success

    def __str__(self):
        """
        String representation of collection

        Returns:
            str

        """
        return "\n".join([str(result) for result in self._results])


class HydraResult(object):
    """
    Contains Hydra Result in convenient format

    """

    def __init__(self, port=None, service=None, host=None, login=None, password=None):
        """
        Init values

        Args:
            port (port):
            service (str):
            host (str):
            login (str):
            password (str):

        """
        self.port = port
        self.service = service
        self.host = host
        self.login = login
        self.password = password

    def __str__(self):
        """
        String representation of Hydra Result

        Returns:
            str

        """
        return "login: {2}\tpassword: {3}".format(self.host, self.port, self.login,
                                                  self.password)
