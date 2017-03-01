import requests

from utils.exceptions import ToucanException, ToucanUnsetException


class Toucan(object):
    SPECIAL_ENDPOINTS = {  # ToDo: remove after add support for multiple keys putting to Toucan
        'service/scans/ports/exclude': 'portdetection',
        'service/scans/ports/include': 'portdetection',
        'service/scans/networks/include': 'portdetection',
        'service/scans/networks/exclude': 'portdetection',
        'service/scans/network_scan_rate': 'portdetection',
        'service/scans/scan_cron': 'portdetection',
    }

    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

    def get(self, key, strict=True):
        """
        Get config from toucan

        Args:
            key (str):

        Returns:
            mixed

        """
        special = False
        toucan_key = "/".join(key.split("."))
        request_key = toucan_key
        if toucan_key in self.SPECIAL_ENDPOINTS:
            request_key = self.SPECIAL_ENDPOINTS[toucan_key]
            special = True

        try:
            response = requests.get(url="{prot}://{host}:{port}/config/aucote/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key=request_key))

            result = self.proceed_response(key, response)
            if special:
                if strict:
                    try:
                        return result["/aucote/{0}".format(toucan_key)]
                    except KeyError:
                        raise ToucanUnsetException

                return_value = []
                for subkey, value in result.items():
                    if subkey.startswith("/aucote/"):
                        subkey = subkey.split("/aucote/")[1].replace("/", ".")

                    return_value.append((subkey, value))
                return return_value

            return result
        except requests.exceptions.ConnectionError:
            raise ToucanException("Cannot connect to Toucan")

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

        if toucan_key in self.SPECIAL_ENDPOINTS:  # ToDo: remove after Toucan multiple keys support
            try:
                data = self.get(self.SPECIAL_ENDPOINTS[toucan_key])
            except ToucanUnsetException:
                data = {}
            data["/aucote/{0}".format(toucan_key)] = value
            toucan_key = self.SPECIAL_ENDPOINTS[toucan_key]
            value = data

        data = {
            "value": value,
        }

        try:
            response = requests.put(url="{prot}://{host}:{port}/config/aucote/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key=toucan_key), json=data)

            return self.proceed_response(key, response)
        except requests.exceptions.ConnectionError:
            raise ToucanException("Cannot connect to Toucan")

    def proceed_response(self, key, response):
        """
        Proceed toucan response

        Args:
            key:
            response:

        Returns:
            mixed - return value if success, else raise exception

        """
        if response.status_code == 404:
            raise ToucanUnsetException(key)

        if response.status_code != 200:
            raise ToucanException(key)

        data = response.json()

        if isinstance(data, dict):
            if data['status'] != "OK":
                raise ToucanException(data['message'])

            return data['value']
        elif isinstance(data, list):
            return_value = []
            for row in data:
                key = row['key']
                value = row['value']
                if key.startswith("/aucote/"):
                    key = key.split("/aucote/")[1].replace("/", ".")

                return_value.append((key, value))
            return return_value
        else:
            raise ToucanException(key)

    def push_config(self, config, key='', overwrite=True):
        """
        Push dict config to the toucan

        Args:
            config(dict):
            key(str): base key
            overwrite(bool): determine if config should be overwrite or not

        Returns:
            None

        """

        for subkey, value in config.items():
            if key:
                new_key = '.'.join([key, subkey])
            else:
                new_key = subkey
                
            if isinstance(value, dict):
                self.push_config(value, new_key, overwrite)
                continue

            if overwrite:
                self.put(new_key, value)
                continue

            try:
                self.get(new_key, strict=True)
                continue
            except ToucanUnsetException:
                self.put(new_key, value)

    def is_special(self, key):
        """
        Check if key is special

        Args:
            key:

        Returns:
            None

        """
        return "/".join(key.split(".")) in self.SPECIAL_ENDPOINTS
