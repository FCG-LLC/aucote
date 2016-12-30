import logging as log
import inotify.adapters

from utils.task import Task


class WatchdogTask(Task):
    def __init__(self, file, action, *args, **kwargs):
        super(WatchdogTask, self).__init__(*args, **kwargs)
        self.file = file.encode("utf-8")
        self.action = action
        self.notifier = inotify.adapters.Inotify()

    def __call__(self, *args, **kwargs):
        self.notifier.add_watch(self.file)

        try:
            for event in self.notifier.event_gen():
                if event is not None:
                    (header, type_names, watch_path, filename) = event
                    if "IN_IGNORED" in type_names:
                        self.notifier.add_watch(self.file)
                    elif {"IN_DELETE_SELF", "IN_MODIFY"}.intersection(set(type_names)):
                        log.info("Detected change of configuration file (%s)!", self.file.decode())
                        self.action(self.file.decode())
        finally:
            self.notifier.remove_watch(self.file)