"""
WatchdogTask is responsible for monitoring files and propagate updates to aucote core.

"""
import logging as log
import inotify.adapters
from inotify.calls import InotifyError

from utils.exceptions import FinishThread
from utils.task import Task


class WatchdogTask(Task):
    """
    Looks on file and propagate updates

    """
    def __init__(self, file, action, *args, **kwargs):
        super(WatchdogTask, self).__init__(*args, **kwargs)
        self.file = file.encode("utf-8")
        self.action = action
        self.notifier = inotify.adapters.Inotify()

    def __call__(self, *args, **kwargs):
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
                    (_, type_names, _, _) = event
                    if "IN_IGNORED" in type_names:
                        self.notifier.add_watch(self.file)
                    elif {"IN_DELETE_SELF", "IN_MODIFY"}.intersection(set(type_names)):
                        log.info("Detected change of configuration file (%s)!", self.file.decode())
                        self.action()
        except FinishThread:
            pass
        finally:
            try:
                self.notifier.remove_watch(self.file)
            except InotifyError:
                log.debug("Inotify Error")
