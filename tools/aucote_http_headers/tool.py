"""
Contains tool class for AucoteHttpHeaders

"""
from tools.aucote_http_headers.tasks import AucoteHttpHeadersTask
from tools.base import Tool


class AucoteHttpHeadersTool(Tool):
    """
    This tool provides tasks for checking HTTP security related headers

    """

    def call(self, *args, **kwargs):
        self.executor.add_task(AucoteHttpHeadersTask(executor=self.executor, port=self.port,
                                                     exploits=self.exploits, config=self.config))
