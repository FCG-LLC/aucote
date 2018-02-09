from threading import Thread, Event
from tornado.gen import sleep
from utils.tftp import TFTP


class TFTPThread(Thread):
    DEFAULT_TIMEOUT = 120  # Time to wait on file in seconds
    DATA_DIR = 'tmp/tftp/'

    def __init__(self, host, port, timeout, min_port, max_port, *args, **kwargs):
        super(TFTPThread, self).__init__(*args, **kwargs)
        self._tftp = TFTP(host, port, timeout, self.DATA_DIR, min_port=min_port, max_port=max_port)
        self.name = "TFTP"
        self.started_event = Event()
        self._close = False

    def __enter__(self):
        self.start()
        self.started_event.wait()
        return self

    def run(self):
        self.started_event.set()
        self._tftp.start()
        self._tftp.listen()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._tftp.stop()
        self.join()

    async def async_get_file(self, address, callback, timeout=DEFAULT_TIMEOUT):
        event = self._tftp.register_address(address, timeout=timeout)

        callback()

        while not event.is_set():
            await sleep(1)

        return self._tftp.get_file(address)
