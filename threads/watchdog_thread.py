"""
Contains thread responsible for monitoring files and propagating updates to aucote core.

"""
import logging as log
from threading import Thread, Lock

import inotify.adapters
from inotify.calls import InotifyError
from inotify.constants import IN_IGNORED, IN_MODIFY, IN_DELETE_SELF


class WatchdogThread(Thread):
    """
    Looks on file and propagate updates

    """
    def __init__(self, file, action):
        super(WatchdogThread, self).__init__()
        self.name = "Watchdog"
        self.file = file.encode("utf-8")
        self.action = action
        self.notifier = inotify.adapters.Inotify()
        self._lock = Lock()
        self._finish = False

    def run(self):
        """
        Listen on self.file and execute self.action if file change

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        self.notifier.add_watch(self.file)

        try:
            for event in self.notifier.event_gen():
                if event is not None:
                    mask = event[0].mask
                    if IN_IGNORED & mask:
                        self.notifier.add_watch(self.file)
                    elif (IN_DELETE_SELF | IN_MODIFY) & mask:
                        log.info("Detected change of configuration file (%s)!", self.file.decode())
                        self.action()
                else:
                    with self._lock:
                        if self._finish:
                            break
        except InotifyError:
            log.debug("Inotify Error")

        finally:
            try:
                self.notifier.remove_watch(self.file)
            except InotifyError:
                pass

    def stop(self):
        """
        Stop thread.

        Returns:
            None

        """
        with self._lock:
            self._finish = True
