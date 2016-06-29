from nanomsg import Socket, PUSH
import struct
import logging as log
from utils.string import bytes_str
from ipaddress import IPv4Address, IPv6Address

class KuduMsg:
    _ENDIANNESS = 'little'
    def __init__(self):
        self._data = bytearray()

    def add_bool(self, val):
        assert val in (True, False)
        self._data.extend(val.to_bytes(1, self._ENDIANNESS))

    def add_byte(self, val):
        assert type(val) == int
        self._data.extend(val.to_bytes(1, self._ENDIANNESS))
    
    def add_short(self, val):
        assert type(val) == int
        self._data.extend(val.to_bytes(2, self._ENDIANNESS))

    def add_int(self, val):
        assert type(val) == int
        self._data.extend(val.to_bytes(4, self._ENDIANNESS))

    def add_long(self, val):
        assert type(val) == int
        self._data.extend(val.to_bytes(8, self._ENDIANNESS))

    def add_str(self, val):
        assert type(val) == str
        b = val.encode('utf-8')
        self.add_short(len(b))
        self._data.extend(b)

    def add_datetime(self, val):
        if val is None:
            self.add_long(0)
            return
        num_timestamp = val.timestamp() #seconds
        num_timestamp = round(1000*num_timestamp) #miliseconds
        self.add_long(num_timestamp)

    def add_ip(self, val):
        assert type(val) in (IPv4Address, IPv6Address)
        if type(val) == IPv4Address:
            val = IPv6Address('2002::%s'%val)
        self._data.extend(val.packed)

class KuduQueue:
    def __init__(self, address):
        self._address = address

    def connect(self):
        #return
        self._socket = Socket(PUSH)
        self._socket.connect(self._address)

    def close(self):
        #return
        self._socket.close()
        self._socket=None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def send_msg(self, msg):
        #return
        assert type(msg) == KuduMsg
        log.debug('sending bytes to kuduworker: %s', bytes_str(msg._data))
        self._socket.send(msg._data)
        