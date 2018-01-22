import logging
import socket
import os
import select
import time
from multiprocessing import Event


log = logging.getLogger()


class TFTPError(Exception):
    """
    TFTP Error. Base class for TFtP related exceptions
    """
    def __init__(self, *args, **kwargs):
        super(TFTPError, self).__init__(*args, **kwargs)


class TFTPTimeoutError(TFTPError):
    def __init__(self, address, *args, **kwargs):
        super(TFTPError, self).__init__(*args, **kwargs)
        self.address = address
        self.msg = 'Timeout Error while waiting for file from {}'.format(address)


class TFTPAlreadyExists(TFTPError):
    def __init__(self, address, *args, **kwargs):
        super(TFTPError, self).__init__(*args, **kwargs)
        self.address = address
        self.msg = 'Already listening on file from {}. Try again later'.format(address)


class TFTPNotFound(TFTPError):
    def __init__(self, address, *args, **kwargs):
        super(TFTPError, self).__init__(*args, **kwargs)
        self.address = address
        self.msg = 'Cannot find request for {}. Make sure anything is waiting on it'.format(address)


class TFTPMaxSizeExceeded(TFTPError):
    def __init__(self, address, *args, **kwargs):
        super(TFTPError, self).__init__(*args, **kwargs)
        self.address = address
        self.msg = 'Maximum file size exceeded for {}'.format(address)


class TFTP:
    """
    Simple TFTP server for obtaining vulnerable data by scripts with TFTP protocol

    Server processes only request from addresses from whitelist. The whitelist is dynamic and to register address use
    `register_address` function. Address can be registered only once till the file is obtained or TimeoutError occurs

    To wait on file and take path, the get_file should be fired. The file should be removed by consumer
    """

    GET_BYTE = 1
    PUT_BYTE = 2

    MAX_BLKSIZE = 0x10000
    MAX_FILE_SIZE = 0x1000  # Max file size in bytes
    TFTP_MIN_DATA_PORT = 44000  # range of UDP data port
    TFTP_MAX_DATA_PORT = 65000  # -//-

    DEF_BLKSIZE = 512  # size of data block in TFTP-packet

    def __init__(self, ip, port, timeout, tmp_dir):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self._dir = tmp_dir
        self._socket = None
        self._current_receive_port = self.TFTP_MIN_DATA_PORT
        self.epoll = select.epoll()
        self.receivers = {}
        self.files = {}
        self._stop = False

    def register_address(self, address, timeout=120):
        """
        Ask server to listen for file from given address. Raises Exception if any script is already waiting on file.

        To get path of given file, using of get_file is required

        """
        event = Event()

        if address in self.files:
            raise TFTPAlreadyExists(address)
        self.files[address] = {
            'event': event,
            'time': int(time.time()) + timeout,
            'exception': None,
            'size': 0
        }

        return event

    def get_file(self, address):
        """
        Get file from specific address if available. If files wasn't downloaded within timeout given to `add_file`
        the TimeoutError is raise

        """
        if address not in self.files:
            raise TFTPNotFound(address)

        event = self.files[address]['event']

        while not event.is_set():
            time.sleep(1)
        return_value = self.files[address]['path']

        try:
            if self.files[address]['exception'] is not None:
                raise self.files[address]['exception']
            return return_value
        finally:
            del self.files[address]

    @property
    def next_receive_port(self):
        """
        Get port number to obtain data from server

        """
        self._current_receive_port += 1
        if self._current_receive_port > self.TFTP_MAX_DATA_PORT:
            self._current_receive_port = self.TFTP_MIN_DATA_PORT

        return self._current_receive_port

    def start(self):
        """
        Start socket
        """
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.settimeout(self.timeout)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.ip, self.port))

    def listen(self):
        """
        Listen for requests using epoll

        """
        self.epoll.register(self._socket, select.EPOLLIN)

        while True:
            events = self.epoll.poll(1)

            for fd, event in events:
                if self._socket.fileno() == fd:
                    if event & select.EPOLLIN:
                        self.handle_new_client()
                else:
                    self.receive_file(fd)

            self.check_timeouts()

            if self._stop:
                self.epoll.close()
                break

    def handle_new_client(self):
        """
        Handle connection on main port

        """
        try:
            buffer, (address, port) = self._socket.recvfrom(self.MAX_BLKSIZE)
        except socket.timeout:
            return
        except socket.error:
            return

        if address not in self.files:
            return

        log.debug('Connection from %s:%s', address, port)

        message_type = buffer[1]

        if message_type == self.GET_BYTE:
            # Reading files is unsupported
            return
        elif message_type == self.PUT_BYTE:
            ss = buffer[2:].split(b'\0')
            filename = ss[0].decode('utf-8')

            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver.settimeout(self.timeout)
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            receiver.bind(('', self.next_receive_port))

            response = b'\x00\x04\x00\x00'

            receiver.sendto(response, (address, port))
            self.epoll.register(receiver.fileno())
            self.files[address]['filename'] = filename
            self.files[address]['path'] = 'tmp/' + str(time.time()) + '_' + filename
            self.files[address]['receiver'] = receiver
            self.receivers[receiver.fileno()] = receiver
        else:
            # Ignore request
            return

    def receive_file(self, fd):
        """
        Receive data on given fd. Append it to cnfigured file
        """
        receiver = self.receivers[fd]
        buffer, (remote_address, remote_port) = receiver.recvfrom(self.MAX_BLKSIZE)
        path = self.files[remote_address]['path']

        self.files[remote_address]['size'] += len(buffer[4:])

        if self.files[remote_address]['size'] > self.MAX_FILE_SIZE:
            self.epoll.unregister(fd)
            receiver.close()
            del self.receivers[fd]
            self.files[remote_address]['exception'] = TFTPMaxSizeExceeded(remote_address)
            self.files[remote_address]['event'].set()
            os.remove(path)
            return

        with open(path, 'ba') as f:
            f.write(buffer[4:])

            response = b'\x00\x04' + buffer[2:4]
            receiver.sendto(response, (remote_address, remote_port))

            if len(buffer[4:]) < self.DEF_BLKSIZE:
                self.epoll.unregister(fd)
                receiver.close()
                del self.receivers[fd]
                self.files[remote_address]['event'].set()

    def check_timeouts(self):
        """
        Check timeouts and clean obsolete data
        """
        current_time = time.time()

        for address, details in self.files.items():
            if details['event'].is_set():
                continue

            if details['time'] > current_time:
                continue

            if 'receiver' in details:
                del self.receivers[details['receiver'].fileno()]
                details['receiver'].close()

            try:
                os.remove(details['path'])
            except:
                pass

            details['exception'] = TFTPTimeoutError(address)
            details['event'].set()

    def stop(self):
        """
        Close and unregister all connections
        """
        for receiver in self.receivers.values():
            self.epoll.unregister(receiver.fileno())
            receiver.close()

        self.epoll.unregister(self._socket.fileno)
        self._socket.close()
        self._stop = True
