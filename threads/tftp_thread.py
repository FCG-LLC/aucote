from threading import Thread, Event

from multiprocessing import Queue

from tornado.gen import sleep

from utils.tftp import TFTP


class TFTPThread(Thread):
    DEFAULT_TIMEOUT = 120  # Time to wait on file in seconds

    def __init__(self):
        super(TFTPThread, self).__init__()
        self._tftp = TFTP('', 6969, 120, 'tmp/')
        self.name = "Storage"
        self._queue = Queue()
        self.started_event = Event()
        self._close = False

    def __enter__(self):
        self.start()
        self.started_event.wait()
        return self

    def run(self):
        self._tftp.start()
        self._tftp.listen()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._tftp.stop()
        self.join()

    async def async_get_file(self, address, timeout=120):
        event = self._tftp.register_address(address, timeout=timeout)

        while not event.is_set():
            await sleep(1)

        return self._tftp.get_file(address)
