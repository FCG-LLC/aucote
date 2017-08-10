"""
Exceptions used by cve-search tool and tasks

"""


class CVESearchApiException(Exception):
    """
    Raises if cannot connect to the cve-search API

    """

    def __init__(self, reason):
        message = "Cannot connect to CVESearch API: {0}".format(reason)

        super(CVESearchApiException, self).__init__(message)
