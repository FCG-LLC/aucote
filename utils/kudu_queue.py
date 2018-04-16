"""
Module responsible for Kudu communication
"""

import logging as log
from ipaddress import IPv4Address, IPv6Address

from utils.database_interface import DbInterface
from utils.string import bytes_str
from nanomsg import Socket, PUSH, DONTWAIT, NanoMsgAPIError  # pylint: disable=no-name-in-module


class KuduMsg:
    """
    Class which represents message for Kudu
    """
    MAGIC_WORD = 0xB7ED  # Reversed order to use in self,_convert_short
    PROTOCOL_VERSION = 0x1

    _ENDIANNESS = 'little'

    def __init__(self, queue_type=None, queue_version=1):
        """
        init variables
        """

        self._data = bytearray()
        self._type = queue_type
        self._version = queue_version

    def _convert_bool(self, val):
        assert isinstance(val, bool)
        return val.to_bytes(1, self._ENDIANNESS)

    def _convert_byte(self, val):
        assert isinstance(val, int)
        return val.to_bytes(1, self._ENDIANNESS)

    def _convert_short(self, val):
        if val is None:
            val = 0
        assert isinstance(val, int)
        return val.to_bytes(2, self._ENDIANNESS)

    def _convert_int(self, val):
        if val is None:
            val = 0

        assert isinstance(val, int)
        return val.to_bytes(4, self._ENDIANNESS)

    def _convert_long(self, val):
        assert isinstance(val, int)
        return val.to_bytes(8, self._ENDIANNESS)

    def _convert_str(self, val=None):
        if val is None:
            val = ''

        assert isinstance(val, str)
        bytestring = val.encode('utf-8')
        return self._convert_short(len(bytestring)) + bytestring

    def _convert_datetime(self, val):
        if val is None:
            return self._convert_long(0)
        return self._convert_long(round(1000*val))

    def _convert_ip(self, val):
        """
        Add ip value to data
        """

        assert isinstance(val, (IPv4Address, IPv6Address))
        if isinstance(val, IPv4Address):
            txt = '2002:%02x%02x:%02x%02x::' % tuple(val.packed)
            val = IPv6Address(txt)
        return val.packed

    def add_bool(self, val):
        """
        Add boolean value to data
        """

        self._data.extend(self._convert_bool(val))

    def add_byte(self, val):
        """
        Add byte to data
        """
        self._data.extend(self._convert_byte(val))

    def add_short(self, val):
        """
        Add short value to data
        """
        self._data.extend(self._convert_short(val))

    def add_int(self, val):
        """
        Add int value to data
        """
        self._data.extend(self._convert_int(val))

    def add_long(self, val):
        """
        Add long value to data
        """
        self._data.extend(self._convert_long(val))

    def add_str(self, val=None):
        """
        Add string value to data
        """
        self._data.extend(self._convert_str(val))

    def add_datetime(self, val):
        """
        Add timestamp value to data

        """
        self._data.extend(self._convert_datetime(val))

    def add_ip(self, val):
        """
        Add ip value to data
        """
        self._data.extend(self._convert_ip(val))

    @property
    def data(self):
        """
        Returns kudu data
        """

        return self._convert_short(self.MAGIC_WORD) + self._convert_short(self.PROTOCOL_VERSION) + \
               self._convert_int(len(self._data)) + self._convert_short(self._type) + \
               self._convert_short(self._version) + self._data


class KuduQueue(DbInterface):
    """
    Represents kudu queue
    """

    def __init__(self, address):
        """
        init variables
        """

        self._address = address
        self._socket = None

    def connect(self):
        """
        Connect to kudu
        """

        self._socket = Socket(PUSH)
        self._socket.connect(self._address)

    def close(self):
        """
        Disconnect from kudu
        """

        self._socket.close()
        self._socket = None

    def send_msg(self, msg, dont_wait=False):
        """
        Send message to queue
        """

        assert isinstance(msg, KuduMsg)
        log.debug('sending bytes to kuduworker: %s', len(msg.data))
        flags = DONTWAIT if dont_wait else 0
        try:
            self._socket.send(msg.data, flags)
        except NanoMsgAPIError:
            log.warning("Nanomessage error. Reconnecting...")
            self.close()
            self.connect()
            self._socket.send(msg.data, flags)
