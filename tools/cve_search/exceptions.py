"""
Exceptions used by cve-search tool and tasks

"""


class CVESearchAPIConnectionException(Exception):
    """
    Raises if cannot connect to the cve-search API

    """

    def __init__(self, reason):
        message = "Cannot connect to CVESearch API: {0}".format(reason)

        super(CVESearchAPIConnectionException, self).__init__(message)



class CVESearchAPIException(Exception):
    """
    Raises if request to API fails

    """

    def __init__(self, response):
        message = "{url} Returns {status}".format(url=response.request.url, status=response.code)

        super(CVESearchAPIException, self).__init__(message)
