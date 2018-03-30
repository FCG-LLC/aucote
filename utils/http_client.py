"""
Asynchronous HTTP client for Aucote. It's using tornado's AsyncHTTPClient.

"""
import logging as log

import functools
from typing import Any

from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPError
import ujson


def retry_if_fail(min_retry_time: int, max_retry_time: int, max_retries: int,
                  exceptions: [Exception, tuple]) -> callable:
    """
    Retry function execution in case of connection fail.
    In case of fail double waiting time starting from min_retry_time.
    Waiting time cannot exceed max_retry_time.
    Raise exception after max_retries failed tries. max_retries has to be more than 1
    """
    def decorator(function: callable) -> callable:

        @functools.wraps(function)
        async def function_wrapper(*args, **kwargs) -> Any:
            """
            Try to execute function. In case of fail double waiting time.
            Waiting time cannot exceed max_retry_time.
            Raise ``ToucanConnectionException`` after max_retries failed tries

            """
            wait_time = min_retry_time
            try_counter = 0
            while try_counter < max_retries:
                try:
                    return await function(*args, **kwargs)
                except exceptions as exception:
                    log.warning("Connection error for %s.%s: %s", args[0].__class__.__name__,
                                function.__name__, exception)
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
    def instance(cls, *args, **kwargs) -> 'HTTPClient':
        """
        Return instance of HTTPClient
        """
        if cls._instance is None:
            cls._instance = HTTPClient(*args, **kwargs)
        return cls._instance

    @classmethod
    def _handle_response(cls, response: 'HTTPResponse') -> 'Future':
        """
        Handle response
        """
        if response.error:
            log.info("Error: %s with requesting %s", response.error, response.request.url)
        return response

    def get(self, url: str, **kwargs) -> 'Future':
        """
        Perform GET request
        """
        return self.request(url=url, method="GET", **kwargs)

    def head(self, url: str, **kwargs) -> 'Future':
        """
        Perform HEAD request
        """
        return self.request(url=url, method="HEAD", **kwargs)

    def put(self, url: str, **kwargs) -> 'Future':
        """
        Perform PUT request
        """
        return self.request(url=url, method="PUT", **kwargs)

    def request(self, json: dict = None, **kwargs) -> 'Future':
        """
        Perform request
        """
        if json:
            kwargs['body'] = ujson.dumps(json)
            kwargs.setdefault('headers', {})['Content-Type'] = 'application/json'
        request = HTTPRequest(**kwargs)
        return AsyncHTTPClient().fetch(request, self._handle_response)

