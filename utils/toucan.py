"""
Toucan is centralized node manager. Aucote use it for obtain user configuration.

"""
import logging as log
import time
import requests


from utils.exceptions import ToucanException, ToucanUnsetException, ToucanConnectionException


def retry_if_fail(function):
    """
    Retry function execution in case of connection fail

    Args:
        function:

    Returns:
        function

    """
    def function_wrapper(*args, **kwargs):
        """
        Try to execute function. In case of fail double waiting time.
        Waiting time cannot exceed Toucan.MAX_RETRY_COUNT.
        Raise exception after Toucan.MAX_RETRY_COUNT failed tries

        Args:
            *args:
            **kwargs:

        Returns:
            mixed

        """
        wait_time = Toucan.MIN_RETRY_TIME
        try_counter = 0
        while try_counter < Toucan.MAX_RETRY_COUNT:
            try:
                return function(*args, **kwargs)
            except ToucanConnectionException:
                log.warning("Cannot connect to Toucan: waiting %s s", wait_time)
                time.sleep(wait_time)
                wait_time *= 2
                if wait_time > Toucan.MAX_RETRY_TIME:
                    wait_time = Toucan.MAX_RETRY_TIME
                try_counter += 1
        raise ToucanConnectionException

    return function_wrapper


class Toucan(object):
    """
    This class integrates Toucan with Aucote

    """
    SPECIAL_ENDPOINTS = {  # ToDo: remove after add support for multiple keys putting to Toucan
    }

    MIN_RETRY_TIME = 5
    MAX_RETRY_TIME = 300
    MAX_RETRY_COUNT = 20

    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

    @retry_if_fail
    def get(self, key, strict=True):
        """
        Get config from toucan

        Args:
            key (str):

        Returns:
            mixed

        """
        toucan_key = "/".join(key.split("."))
        request_key = toucan_key

        try:
            response = requests.get(url="{prot}://{host}:{port}/config/aucote/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key=request_key))

            result = self.proceed_response(key, response)
            if self.is_special(key):
                return_value = {}
                for subkey, value in result.items():
                    if subkey.startswith("/aucote/"):
                        subkey = subkey.split("/aucote/")[1].replace("/", ".")

                    return_value[subkey] = value
                return return_value

            return result
        except requests.exceptions.ConnectionError:
            raise ToucanConnectionException("Cannot connect to Toucan")

    @retry_if_fail
    def put(self, key, value):
        """
        Put config into toucan

        Args:
            key (str):
            value (str):

        Returns:
            mixed - inserted value if success

        """
        toucan_key = "/".join(key.split("."))

        if not self.is_special(key):
            data = {
                "value": value,
            }
        else:
            data = value

        try:
            response = requests.put(url="{prot}://{host}:{port}/config/aucote/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key=toucan_key), json=data)

            return self.proceed_response(key, response)
        except requests.exceptions.ConnectionError:
            raise ToucanConnectionException("Cannot connect to Toucan")

    def proceed_response(self, key, response):
        """
        Proceed toucan response

        Args:
            key:
            response:

        Returns:
            mixed - return value if success, else raise exception

        """
        if response.status_code in {404, 204}:
            raise ToucanUnsetException(key)

        if response.status_code != 200:
            raise ToucanException(key)

        data = response.json()

        if isinstance(data, dict):
            if data['status'] != "OK":
                raise ToucanException(data['message'])

            return data['value']
        elif isinstance(data, list):
            return_value = {}
            for row in data:
                key = row['key']
                value = row['value']
                if key.startswith("/aucote/"):
                    key = key.split("/aucote/")[1].replace("/", ".")

                return_value[key] = value
            return return_value
        else:
            raise ToucanException(key)

    def push_config(self, config, prefix='', overwrite=True):
        """
        Push dict config to the toucan

        Args:
            config(dict):
            prefix(str): base key
            overwrite(bool): determine if config should be overwrite or not

        Returns:
            None

        """

        parsed_config = self.prepare_config(config, prefix)

        for key, value in parsed_config.items():
            if overwrite:
                self.put(key, value)
                continue

            try:
                self.get(key, strict=True)
                continue
            except ToucanUnsetException:
                self.put(key, value)

    def prepare_config(self, config, prefix=''):
        """
        Convert config to list of objects with key and value.

        Args:
            config (dict):
            prefix (str):

        Returns:
            dict - configuration keys: {key: value, key_2:value_2 (, ...)}

        """
        return_value = {}

        for subkey, value in config.items():
            if prefix:
                new_key = '.'.join([prefix, subkey])
            else:
                new_key = subkey

            if isinstance(value, dict):
                return_value.update(self.prepare_config(value, new_key))
                continue

            return_value[new_key] = value

        return return_value

    def is_special(self, key):
        """
        Check if key is special

        Args:
            key:

        Returns:
            None

        """
        return key.endswith(".*")
