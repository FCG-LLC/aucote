"""
Toucan is centralized node manager. Aucote uses it to obtain user configuration.

"""
import logging as log
import time
import ujson
from tornado.httpclient import HTTPError

from utils.exceptions import ToucanException, ToucanUnsetException, ToucanConnectionException
from utils.http_client import HTTPClient, retry_if_fail


class Toucan(object):
    """
    This class integrates Toucan with Aucote

    """
    min_retry_time = 5
    max_retry_time = 300
    max_retry_count = 20
    PREFIX = "aucote"

    def __init__(self, api):
        self.api = api.rstrip("/")
        self._http_client = HTTPClient.instance()

    def _handle_exception(self, key, exception):
        if not exception.response:
            raise ToucanConnectionException(str(exception))
        if exception.response.code in {404, 204}:
            raise ToucanUnsetException(key)

        if exception.response.code == 502:
            try:
                data = ujson.loads(exception.response.body.decode())
            except ValueError:
                raise ToucanConnectionException("Cannot parse JSON response: '{0}'".
                                                format(exception.response.body.decode()))
            raise ToucanConnectionException(data['message'])

        raise ToucanException(key)

    @retry_if_fail(min_retry_time=min_retry_time, max_retry_time=max_retry_time, max_retries=max_retry_count,
                   exceptions=ToucanConnectionException)
    async def get(self, key):
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
            response = await self._http_client.get(url="{api}/config/{key}".format(api=self.api, key=toucan_key))

            result = self.proceed_response(key, response)
            strip_key = key.rstrip(".*")

            if isinstance(result, dict) and strip_key in result.keys():
                del result[strip_key]

                if not result:
                    result[strip_key] = {}

            return result

        except HTTPError as exception:
            self._handle_exception(key, exception)
        except (ConnectionError, OSError) as exception:
            raise ToucanConnectionException(str(exception))

    @retry_if_fail(min_retry_time=min_retry_time, max_retry_time=max_retry_time, max_retries=max_retry_count,
                   exceptions=ToucanConnectionException)
    async def put(self, key, values):
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
        toucan_key = self._get_slash_separated_key(key, strip_slashes=True) if key != "*" else key

        if key != "*":
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
            response = await self._http_client.put(url="{api}/config/{key}".format(api=self.api, key=toucan_key),
                                                   json=data)

            return self.proceed_response(key, response)

        except HTTPError as exception:
            self._handle_exception(key, exception)
        except ConnectionError as exception:
            raise ToucanConnectionException(str(exception))

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
        data = ujson.loads(response.body.decode())

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

    async def push_config(self, config, prefix='', overwrite=False):
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
            await self.put("*", parsed_config)
            return

        try:
            all_keys = await self.get("*".format(prefix=self.PREFIX))
        except ToucanUnsetException:
            all_keys = {}

        for key in all_keys:
            if key in parsed_config.keys():
                del parsed_config[key]

        if parsed_config:
            await self.put("*", parsed_config)

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
