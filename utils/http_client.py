"""
Asynchronous HTTP client for Aucote. It's using tornado's AsyncHTTPClient.

"""
import logging as log
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
import ujson


class HTTPClient(object):
    """
    Asynchronous HTTP client for Aucote. It's using tornado's AsyncHTTPClient.

    """
    _instance = None

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
            log.info("Error: %s with requesting %s", response.error, response.request.url)
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
        Perform PUT request

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
        return AsyncHTTPClient().fetch(request, self._handle_response)
