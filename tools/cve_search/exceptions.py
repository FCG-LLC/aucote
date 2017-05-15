class CVESearchAPIConnectionException(Exception):
    """
    Raises if cannot connect to the cve-search API

    """


class CVESearchAPIException(Exception):
    """
    Raises if request to API fails

    """

    def __init__(self, response):
        message = "{url} Returns {status}".format(url=response.url, status=response.status_code)

        super(CVESearchAPIException, self).__init__(message)
