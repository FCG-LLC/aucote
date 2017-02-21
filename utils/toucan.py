import requests

from utils.exceptions import ToucanException


class Toucan(object):
    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

    def get(self, key):
        """
        Get config from toucan

        Args:
            key (str):

        Returns:
            mixed

        """
        try:
            response = requests.get(url="{prot}://{host}:{port}/config/aucote/{key}"
                                    .format(prot=self.protocol, host=self.host, port=self.port,
                                            key="/".join(key.split("."))))

            return self.proceed_response(key, response)
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
        if response.status_code != 200:
            raise ToucanException(key)

        data = response.json()

        if data['status'] != "OK":
            raise ToucanException(data['message'])

        return data['value']
