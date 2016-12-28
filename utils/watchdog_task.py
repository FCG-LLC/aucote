from time import sleep

from utils.task import Task


class WatchdogTask(Task):
    def __init__(self, file, *args, **kwargs):
        super(WatchdogTask, self).__init__(*args, **kwargs)
        self.file = file

    def __call__(self, *args, **kwargs):
        while 1:
            sleep(10)
            print("waiting")