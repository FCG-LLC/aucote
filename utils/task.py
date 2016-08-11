class Task(object):
    def __init__(self, executor):
        self.executor = executor

    @property
    def kudu_queue(self):
        return self.executor.kudu_queue

    @property
    def exploits(self):
        return self.executor.exploits

    def __call__(self, *args, **kwargs):
        raise NotImplementedError