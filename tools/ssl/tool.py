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
        """
        self.context.add_task(SSLScriptTask(context=self.context, port=self.port, scan=self._scan,
                                            exploits=[self.aucote.exploits.find('testssl', 'testssl')]))
