"""
Module responsible for Kudu communication
"""

import logging as log
from ipaddress import IPv4Address, IPv6Address

from utils.database_interface import DbInterface
from utils.string import bytes_str
from nanomsg import Socket, PUSH


class KuduMsg:
    """
    Class which represents message for Kudu
    """
    _ENDIANNESS = 'little'
    def __init__(self):
        """
        init variables
        """
        self._data = bytearray()

    def add_bool(self, val):
        """
        Add boolean value to data
        """
        assert isinstance(val, bool)
        self._data.extend(val.to_bytes(1, self._ENDIANNESS))

    def add_byte(self, val):
        """
        Add byte to data
        """
        assert isinstance(val, int)
        self._data.extend(val.to_bytes(1, self._ENDIANNESS))

    def add_short(self, val):
        """
        Add short value to data
        """
        assert isinstance(val, int)
        self._data.extend(val.to_bytes(2, self._ENDIANNESS))

    def add_int(self, val):
        """
        Add int value to data
        """
        assert isinstance(val, int)
        self._data.extend(val.to_bytes(4, self._ENDIANNESS))

    def add_long(self, val):
        """
        Add long value to data
        """
        assert isinstance(val, int)
        self._data.extend(val.to_bytes(8, self._ENDIANNESS))

    def add_str(self, val):
        """
        Add string value to data
        """
        assert isinstance(val, str)
        bytestring = val.encode('utf-8')
        self.add_short(len(bytestring))
        self._data.extend(bytestring)

    def add_datetime(self, val):
        """
        Add datetime value to data
        """
        if val is None:
            self.add_long(0)
            return
        num_timestamp = val.timestamp() #seconds
        num_timestamp = round(1000*num_timestamp) #miliseconds
        self.add_long(num_timestamp)

    def add_ip(self, val):
        """
        Add ip value to data
        """
        assert isinstance(val, (IPv4Address, IPv6Address))
        if isinstance(val, IPv4Address):
            txt = '2002:%02x%02x:%02x%02x::'%tuple(val.packed)
            val = IPv6Address(txt)
        self._data.extend(val.packed)

    @property
    def data(self):
        return self._data


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

    def send_msg(self, msg):
        """
        Send message to queue
        """
        assert isinstance(msg, KuduMsg)
        log.debug('sending bytes to kuduworker: %s', bytes_str(msg.data))
        self._socket.send(msg.data)
