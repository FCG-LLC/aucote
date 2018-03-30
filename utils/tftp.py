"""
There is some tool which sends request to the switch/router.
When device take this request it sends the file (e.g. configuration) to the TFTP as a response.
Server is needed to confirm and to prove vulnerability.

"""
import logging
import socket
import os
import select
import time
from threading import Event


log = logging.getLogger('aucote.tftp')


class TFTPError(Exception):
    """
    Base class for TFTP server related exceptions
    """
    def __init__(self, *args, **kwargs):
        super(TFTPError, self).__init__(*args, **kwargs)


class TFTPTimeoutError(TFTPError):
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.msg = 'Timeout Error while waiting for file from {}'.format(address)
        super(TFTPError, self).__init__(self.msg, *args, **kwargs)


class TFTPAlreadyExists(TFTPError):
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.msg = 'Already listening on file from {}. Try again later'.format(address)
        super(TFTPError, self).__init__(self.msg, *args, **kwargs)


class TFTPNotFound(TFTPError):
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.msg = 'Cannot find request for {}. Make sure anything is waiting on it'.format(address)
        super(TFTPError, self).__init__(self.msg, *args, **kwargs)


class TFTPMaxSizeExceeded(TFTPError):
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.msg = 'Maximum file size exceeded for {}'.format(address)
        super(TFTPError, self).__init__(self.msg, *args, **kwargs)


class TFTP:
    """
    Simple TFTP server for obtaining vulnerable data by scripts with TFTP protocol (RFC 1350)

    Server processes only request from whitelisted addresses.
    An address can be whitelisted by `register_address` function.
    Address can be registered only once till the file is obtained or TimeoutError occurs

    If file was sent from specific address, it can be obtain by `get_file`.
    The file should be removed by consumer
    """

    GET_BYTE = 1
    PUT_BYTE = 2

    MAX_BLKSIZE = 0x10000
    MAX_FILE_SIZE = 0x100000  # Max file size in bytes

    OPCODE_LEN = BLOCK_NUMBER_LEN = 2
    PREFIX_LEN = OPCODE_LEN + BLOCK_NUMBER_LEN

    DEF_BLKSIZE = 512  # size of data block in TFTP-packet

    def __init__(self, ip, port, timeout, data_dir, min_port, max_port):
        self.ip = ip
        self.port = port
        self._timeout = timeout
        self._dir = data_dir
        self._socket = None
        self._min_port = min_port
        self._max_port = max_port
        self._current_receive_port = self._min_port
        self._epoll = select.epoll()
        self._receivers = {}
        self._files = {}
        self._stop = False

    def register_address(self, address, timeout=120):
        """
        Ask server to listen for file from given address. Raises Exception if any script is already waiting on file.

        To get path of received file, using of get_file is required

        """
        event = Event()

        if address in self._files:
            raise TFTPAlreadyExists(address)
        self._files[address] = {
            'event': event,
            'time': int(time.time()) + timeout,
            'exception': None,
            'size': 0
        }

        log.debug('Add %s to the TFTP server', address)

        return event

    def get_file(self, address):
        """
        Get file from specific address if available. If file wasn't downloaded within timeout given to `add_file`
        the TimeoutError is raise

        """
        if address not in self._files:
            raise TFTPNotFound(address)

        event = self._files[address]['event']

        while not event.is_set():
            time.sleep(1)
        return_value = self._files[address].get('path')

        try:
            if self._files[address]['exception'] is not None:
                raise self._files[address]['exception']
            return return_value
        finally:
            del self._files[address]

    @property
    def next_receive_port(self):
        """
        Get port number to obtain data from server

        """
        self._current_receive_port += 1
        if self._current_receive_port > self._max_port:
            self._current_receive_port = self._min_port

        return self._current_receive_port

    def start(self):
        """
        Start socket

        """
        self._socket = self._open_port(self.ip, self.port)

        os.makedirs(self._dir, exist_ok=True)

    def listen(self):
        """
        Listen for requests using epoll

        """
        self._epoll.register(self._socket, select.EPOLLIN)

        while True:
            events = self._epoll.poll(1)

            for fd, event in events:
                if self._socket.fileno() == fd:
                    if event & select.EPOLLIN:
                        self.handle_new_client()
                else:
                    self.receive_file(fd)

            self.check_timeouts()

            if self._stop:
                self._epoll.close()
                break

    def handle_new_client(self):
        """
        Handle connection on main port

        """
        try:
            buffer, (address, port) = self._socket.recvfrom(self.MAX_BLKSIZE)
        except OSError:
            # Dont do anything in case of socket timeout/error
            log.warning("Error while obtaining data by TFTP server")
            return

        if address not in self._files:
            # Unexpected packet, do nothing
            log.warning("TFTP server got packet from unexpected address: %s", address)
            return

        log.debug('Connection from %s:%s', address, port)

        message_type = buffer[1]

        if message_type == self.GET_BYTE:
            # Reading files is unsupported
            return
        elif message_type == self.PUT_BYTE:
            ss = buffer[self.OPCODE_LEN:].split(b'\0')
            filename = ss[0].decode('utf-8')

            receiver = self._open_port('', self.next_receive_port)

            # Send ACK
            response = b'\x00\x04\x00\x00'

            receiver.sendto(response, (address, port))
            self._epoll.register(receiver.fileno())
            self._files[address]['filename'] = filename
            self._files[address]['path'] = 'tmp/{}_{}'.format(time.time(), filename)
            self._files[address]['receiver'] = receiver
            self._receivers[receiver.fileno()] = receiver
        else:
            # Ignore request
            return

    def receive_file(self, fd):
        """
        Receive data on given fd. Append it to configured file
        """
        receiver = self._receivers[fd]
        buffer, (remote_address, remote_port) = receiver.recvfrom(self.MAX_BLKSIZE)
        path = self._files[remote_address]['path']

        log.debug("Receiving data from %s", remote_address)

        self._files[remote_address]['size'] += len(buffer[self.PREFIX_LEN:])

        if self._files[remote_address]['size'] > self.MAX_FILE_SIZE:
            # Too big file from client, close connection
            self._files[remote_address]['exception'] = TFTPMaxSizeExceeded(remote_address)
            self._close_receiver(fd, remote_address)
            os.remove(path)
            return

        with open(path, 'ba') as f:
            f.write(buffer[self.PREFIX_LEN:])

            # send ACK
            response = b'\x00\x04' + buffer[self.OPCODE_LEN:self.PREFIX_LEN]
            receiver.sendto(response, (remote_address, remote_port))

            if len(buffer[self.PREFIX_LEN:]) < self.DEF_BLKSIZE:
                self._close_receiver(fd, remote_address)

    def _close_receiver(self, fd, remote_address):
        """
        Close receiver basing on fd and remote_address

        """
        log.debug('Closing receiver')
        self._epoll.unregister(fd)
        self._receivers[fd].close()
        del self._receivers[fd]
        self._files[remote_address]['event'].set()

    def check_timeouts(self):
        """
        Check timeouts and clean obsolete data (used for process requests and save file)
        """
        current_time = time.time()

        for address, details in self._files.items():
            if details['event'].is_set():
                continue

            if details['time'] > current_time:
                continue

            if 'receiver' in details:
                del self._receivers[details['receiver'].fileno()]
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
        for receiver in self._receivers.values():
            self._epoll.unregister(receiver.fileno())
            receiver.close()

        if self._socket is not None:
            self._epoll.unregister(self._socket.fileno())
            self._socket.close()

        self._stop = True

    def _open_port(self, host, port):
        log.warning('Opening port (%s, %s)', host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self._timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return sock
