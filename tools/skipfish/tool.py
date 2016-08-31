from tools.base import Tool
from tools.skipfish.tasks import SkipfishScanTask


class SkipfishTool(Tool):
    """
    Skipfish is an active web application security reconnaissance tool. This class integrate it with aucote.
    """

    def __call__(self, *args, **kwargs):

        self.executor.add_task(SkipfishScanTask(executor=self.executor, port=self.port))
