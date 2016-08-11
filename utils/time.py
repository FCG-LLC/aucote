import logging as log
from datetime import timedelta
import time

_MARKERS = {
    'd': 'days',
    'h': 'hours',
    'm': 'minutes',
    's': 'seconds'
}


def parse_period(txt):
    values = {}
    while txt:
        for num, ch in enumerate(txt):
            if ch in _MARKERS:
                values[_MARKERS[ch]] = int(txt[:num])
                txt = txt[num+1:]
                break

    return timedelta(**values)


class PeriodicTimer:
    """
    Calls provided callback once per configured period
    """

    def __init__(self, period, callback):
        """
        Args:
            period(timedelta) - how often to call the callback
            callback(callable) - the function/method/callable that will be called
        """
        self._period = period.total_seconds()
        self._callback = callback

    def loop(self, delay=None):
        """
        Args:
            delay(timedelta) - optional delay of the first call to the callback
        """
        delay_sec = delay.total_seconds() if delay is not None else 0
        while True:
            if delay_sec > 0:
                time.sleep(delay_sec)
            last_call = time.monotonic()
            try:
                self._callback()
            except Exception as err:
                log.warning('Exception %s while executing callback of periodic timer', exc_info=err)
            delay_sec = self._period - (time.monotonic() - last_call)
