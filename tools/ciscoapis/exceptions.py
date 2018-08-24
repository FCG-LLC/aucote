"""
Exceptions used by ciscoapis tool and tasks

"""


class CiscoApiException(Exception):
    """
    Raises if cannot connect to the ciscoapis API

    """

    def __init__(self, reason):
        message = "Cannot connect to ciscoapis: {0}".format(reason)

        super(CiscoApiException, self).__init__(message)
