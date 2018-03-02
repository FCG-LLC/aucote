from tornado.ioloop import IOLoop


class ToucanMonitor:
    THROTTLE_POLL_TIME = 60

    def __init__(self, toucan, ioloop=None):
        self.toucan = toucan
        self._toucan_keys = {}
        self._ioloop = ioloop if ioloop is not None else IOLoop.current()

    def register_toucan_key(self, key, callback, default, add_prefix=True):
        self._toucan_keys[key] = {
            'callback': callback,
            'default': default,
            'add_prefix': add_prefix
        }

    async def monitor(self):
        """
        Poll Toucan for given keys. Request for value, pass to callback and run again in THROTTLE_POLL_TIME secs.
        Request is synchronous, to freeze if Toucan in unreachable.
        If exception occurs, the default value is passed to the callback
        """
        try:
            for key, details in self._toucan_keys.items():
                try:
                    value = self.toucan.get(key, add_prefix=details['add_prefix'])
                except Exception:  # pylint: disable=broad-except
                    value = details['default']

                details['callback'](key=key, value=value)
        finally:
            self._ioloop.call_later(self.THROTTLE_POLL_TIME, self.monitor)

    def start(self):
        self._ioloop.add_callback(self.monitor)
