"""
Contains tool class for AucoteHttpHeaders

"""
from aucote_cfg import cfg
from tools.aucote_http_headers.structs import HeaderDefinitions
from tools.aucote_http_headers.tasks import AucoteHttpHeadersTask
from tools.base import Tool


class AucoteHttpHeadersTool(Tool):
    """
    This tool provides tasks for checking HTTP security related headers

    """

    def call(self, *args, **kwargs):
        self.executor.add_task(AucoteHttpHeadersTask(executor=self.executor, port=self.port,
                                                     exploit=self.exploits, config=self.config))

    @classmethod
    def load(cls, config, exploits):
        """
        Loads configuration after Aucote initialization

        Args:
            config (dict):

        Returns:
            None

        """
        config['headers'] = HeaderDefinitions(cfg.get('tools.aucote-http-headers.headers'), exploits)
