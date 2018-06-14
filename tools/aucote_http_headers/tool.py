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
        self.context.add_task(AucoteHttpHeadersTask(context=self.context, port=self.port,
                                                    exploits=self.exploits, config=self.config))
