"""
Toucan is centralized node manager. Aucote uses it to obtain user configuration.

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

        Raises:
            ToucanConnectionException

        """
        wait_time = Toucan.MIN_RETRY_TIME
        try_counter = 0
        while try_counter < Toucan.MAX_RETRY_COUNT:
            try:
                return function(*args, **kwargs)
            except ToucanConnectionException as exception:
                log.warning("Cannot connect to Toucan: %s", str(exception))
                log.warning("Retry in %s s", wait_time)
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
    MIN_RETRY_TIME = 5
    MAX_RETRY_TIME = 300
    MAX_RETRY_COUNT = 20
    PREFIX = "aucote"

    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

    @retry_if_fail
    def get(self, key):
        """
        Get config from toucan

        Args:
            key (str): Key in dot separated format

        Returns:
            mixed

        Raises:
            ToucanConnectionException

        """
        toucan_key = self._get_slash_separated_key(key, strip_slashes=True)

        try:
            response = requests.get(url="{prot}://{host}:{port}/config/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key=toucan_key))

            result = self.proceed_response(key, response)

            if isinstance(result, dict) and key.rstrip(".*") in result.keys():
                del result[key.rstrip(".*")]

                if not len(result):
                    result[key.rstrip(".*")] = {}

            return result
        except requests.exceptions.ConnectionError:
            raise ToucanConnectionException("Cannot connect to Toucan")

    @retry_if_fail
    def put(self, key, values):
        """
        Put config into toucan

        Args:
            key (str): Key in dot separated format
            values (object):

        Returns:
            mixed - inserted value if success

        Raises:
            ToucanException|ToucanConnectionException

        """
        toucan_key = self._get_slash_separated_key(key, strip_slashes=True) if key is not "*" else key

        if key is not "*":
            data = {
                "value": values,
            }
        elif isinstance(values, dict):
            data = []
            for multikey, multivalue in values.items():
                data.append({
                    'key': self._get_slash_separated_key(multikey),
                    'value': multivalue
                })
        else:
            raise ToucanException("Wrong value for special endpoint ({0})".format(key))

        try:
            response = requests.put(url="{prot}://{host}:{port}/config/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key=toucan_key), json=data)

            return self.proceed_response(key, response)
        except requests.exceptions.ConnectionError:
            raise ToucanConnectionException("Cannot connect to Toucan")

    def proceed_response(self, key, response):
        """
        Proceed toucan response

        Args:
            key: Key in dot separated format
            response:

        Returns:
            mixed - return value if success

        Raises:
            ToucanUnsetException|ToucanConnectionException|ToucanException

        """
        if response.status_code in {404, 204}:
            raise ToucanUnsetException(key)

        if response.status_code == 502:
            data = response.json()
            raise ToucanConnectionException(data['message'])

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
                key = self._get_dot_separated_key(row['key'])

                if row['status'] != "OK":
                    log.warning("Error while obtaining %s from toucan", key)
                    continue

                value = row['value']
                return_value[key] = value
            return return_value
        else:
            raise ToucanException(key)

    def push_config(self, config, prefix='', overwrite=False):
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
        if overwrite:
            self.put("*", parsed_config)
            return

        try:
            all_keys = self.get("*".format(prefix=self.PREFIX))
        except ToucanUnsetException:
            all_keys = {}

        for key in all_keys:
            if key in parsed_config.keys():
                del parsed_config[key]

        if parsed_config:
            self.put("*", parsed_config)

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

            if isinstance(value, dict) and value != {}:
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
        return key.endswith("*")

    def _get_dot_separated_key(self, key, strip_prefix=True):
        """
        Convert Toucan key to Aucote key and strip prefix if required

        Args:
            key (str): Key in dot separated format
            strip_prefix (bool):

        Returns:
            str

        """
        return_value = key
        if strip_prefix and return_value.startswith("/{prefix}/".format(prefix=self.PREFIX)):
            return_value = return_value[len(self.PREFIX)+2:]

        return return_value.replace("/", ".")

    def _get_slash_separated_key(self, key, add_prefix=True, strip_slashes=False):
        """
        Convert Aucote key to Toucan key and add prefix if required

        Args:
            key (str): Key in slash separated format
            add_prefix (bool):
            strip_first_slash (bool): Should be first slash stripped

        Returns:

        """
        return_value = "/{prefix}/".format(prefix=self.PREFIX) if add_prefix else ""
        return_value = "{prefix}{key}".format(prefix=return_value, key=key.replace(".", "/"))
        return return_value.strip("/") if strip_slashes else return_value
