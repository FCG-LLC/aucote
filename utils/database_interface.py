"""
Provide database interface
"""


class DbInterface(object):
    """
    Provide database interface
    """

    def connect(self):
        """
        Connect method
        """
        raise NotImplementedError

    def close(self):
        """
        Close method
        """
        raise NotImplementedError

    def __enter__(self):
        """
        Connect to db while entering by with statement
        """
        self.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """
        Disconnect from db while exiting from with statement
        """
        self.close()
