from nanomsg import Socket, PUSH
import struct
import logging as log
from utils.string import bytes_str

class KuduMsg:
    _ENDIANNESS = 'little'
    def __init__(self):
        self._data = bytearray()

    def add_bool(self, val):
        assert val in (True, False)
        self._data.extend(to_bytes(1, self._ENDIANNESS))
    
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

class KuduQueue:
    def __init__(self, address):
        self._address = address

    def connect(self):
        self._socket = Socket(PUSH)
        self._socket.connect(self._address)

    def close(self):
        self._socket.close()
        self._socket=None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def send_msg(self, msg):
        assert type(msg) == KuduMsg
        log.debug('sending bytes to kuduworker: %s', bytes_str(msg._data))
        self._socket.send(msg._data)
        