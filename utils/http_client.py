"""
Asynchronous HTTP client for Aucote. It's using tornado's AsyncHTTPClient.

"""
import logging as log
from tornado.httpclient import AsyncHTTPClient
from tornado.httpclient import HTTPRequest
import ujson


class HTTPClient(object):
    """
    Asynchronous HTTP client for Aucote. It's using tornado's AsyncHTTPClient.

    """
    _instance = None

    def __init__(self):
        self._client = AsyncHTTPClient()

    @classmethod
    def instance(cls, *args, **kwargs):
        """
        Return instance of HTTPClient

        Returns:
            HTTPClient

        """
        if cls._instance is None:
            cls._instance = HTTPClient(*args, **kwargs)
        return cls._instance

    @classmethod
    def _handle_response(cls, response):
        """
        Handle response

        Args:
            response(HTTPResponse):

        Returns:
            Future -> tornado.httpclient.HTTPResponse

        """
        if response.error:
            log.error("Error: %s" % response.error)
        return response

    def get(self, url, **kwargs):
        """
        Perform GET request

        Args:
            url (str):
            **kwargs: additional HTTPRequest parameters

        Returns:
            Future -> tornado.httpclient.HTTPResponse

        """
        return self.request(url=url, method="GET", **kwargs)

    def head(self, url, **kwargs):
        """
        Perform HEAD request

        Args:
            url (str):
            **kwargs: additional HTTPRequest parameters

        Returns:
            Future -> tornado.httpclient.HTTPResponse

        """
        return self.request(url=url, method="HEAD", **kwargs)

    def put(self, url, **kwargs):
        """
        Perform HEAD request

        Args:
            url (str):
            **kwargs: additional HTTPRequest parameters

        Returns:
            Future -> tornado.httpclient.HTTPResponse

        """
        return self.request(url=url, method="PUT", **kwargs)

    def request(self, json=None, **kwargs):
        """
        Perform request

        Args:
            request (tornado.httpclient.HTTPRequest):

        Returns:
            Future -> tornado.httpclient.HTTPResponse

        """
        if json:
            kwargs['body'] = ujson.dumps(json)
            kwargs.setdefault('headers', {})['Content-Type'] = 'application/json'
        request = HTTPRequest(**kwargs)
        return self._client.fetch(request, self._handle_response)
