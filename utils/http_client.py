"""
Asynchronous HTTP client for Aucote. It's using tornado's AsyncHTTPClient.

"""
import logging as log

import functools
from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPError
import ujson


def retry_if_fail(min_retry_time, max_retry_time, max_retries, exceptions):
    """
    Retry function execution in case of connection fail.
    In case of fail double waiting time starting from min_retry_time.
    Waiting time cannot exceed max_retry_time.
    Raise exception after max_retries failed tries. max_retries has to be more than 1

    Args:
        function (callable):
        min_retry_time (int):
        max_retry_time (int):
        max_retries (int):
        exceptions (Exception|tuple):

    Returns:
        callable

    """
    def decorator(function):
        """

        Args:
            function:

        Returns:
            function

        """
        @functools.wraps(function)
        async def function_wrapper(*args, **kwargs):
            """
            Try to execute function. In case of fail double waiting time.
            Waiting time cannot exceed max_retry_time.
            Raise exception after max_retries failed tries

            Args:
                *args:
                **kwargs:

            Returns:
                mixed

            Raises:
                ToucanConnectionException

            """
            wait_time = min_retry_time
            try_counter = 0
            while try_counter < max_retries:
                try:
                    return await function(*args, **kwargs)
                except exceptions as exception:
                    log.warning("Connection error: %s", str(exception))
                    log.warning("Retry in %s s", wait_time)
                    await gen.sleep(wait_time)
                    wait_time = min(wait_time*2, max_retry_time)
                    try_counter += 1

                    if try_counter >= max_retries:
                        raise exception

        return function_wrapper
    return decorator


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

