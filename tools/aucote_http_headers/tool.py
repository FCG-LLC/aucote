"""
Contains tool class for AucoteHttpHeaders

"""
from tools.aucote_http_headers.tasks import AucoteHttpHeadersTask
from tools.base import Tool


class AucoteHttpHeadersTool(Tool):
    """
    This tool provides tasks for checking HTTP security related headers

    """
    async def call(self, *args, **kwargs):
        self.context.add_task(AucoteHttpHeadersTask(aucote=self.aucote, port=self.port, scan=self._scan,
                                                    exploits=self.exploits, config=self.config))
