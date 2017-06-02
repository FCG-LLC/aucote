"""
Contains tool class for AucoteHttpHeaders

"""
from tools.aucote_http_headers.tasks import AucoteHttpHeadersTask
from tools.base import Tool


class AucoteHttpHeadersTool(Tool):
    """
    This tool provides tasks for checking HTTP security related headers

    """

    def call(self):
        self.aucote.add_task(AucoteHttpHeadersTask(aucote=self.aucote, port=self.port,
                                                   exploits=self.exploits, config=self.config))
