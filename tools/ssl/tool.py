"""
Main file of testssl integration

"""
from tools.base import Tool
from tools.ssl.tasks import SSLScriptTask


class SSLTool(Tool):
    """
    Entrypoint for testssl integration

    """
    async def call(self, *args, **kwargs):
        """
        Prepares tasks for executing

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        self.aucote.add_async_task(SSLScriptTask(aucote=self.aucote, port=self.port,
                                           exploits=[self.aucote.exploits.find('testssl', 'testssl')]))
