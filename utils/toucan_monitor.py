import logging

from tornado.ioloop import IOLoop


log = logging.getLogger(None)


class ToucanMonitor:
    """
    Monitor Toucan for keys added via `register_toucan_key` and perform action related to it
    """
    THROTTLE_POLL_TIME = 60

    def __init__(self, toucan, ioloop=None):
        self.toucan = toucan
        self._toucan_keys = {}
        self._ioloop = ioloop if ioloop is not None else IOLoop.current()

    def register_toucan_key(self, key, callback, default, add_prefix=True):
        """
        Register key for monitoring. The callback is executed even if value didn't changed, so basically it means
        for every poll. (See monitor docstring)

        ToDo: Move class to pycslib with improved behavior. It should be an additional option to call callback only if
        value change

        """
        if self._toucan_keys.get(key) is None:
            self._toucan_keys[key] = {
                'callbacks': [callback],
                'default': default,
                'add_prefix': add_prefix
            }
        else:
            self._toucan_keys[key]['callbacks'].append(callback)

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

                failed_callbacks = []
                for callback in details['callbacks']:
                    try:
                        callback(key=key, value=value)
                    except Exception:  # pylint: disable=broad-except
                        failed_callbacks.append(str(Exception))

                if failed_callbacks:
                    log.error('\n'.join(failed_callbacks))
        finally:
            self._ioloop.call_later(self.THROTTLE_POLL_TIME, self.monitor)

    def start(self):
        self._ioloop.add_callback(self.monitor)
