"""
Defines abstract Tool class

"""
from utils.task import Task


class Tool(Task):
    """
    Tool is a object, which can execute one of more scripts, e.g. Nmap, Hydra

    """
    def __init__(self, exploits: list, port: 'Port', config: dict, *args, **kwargs):
        """
        Init values needed to run and proceed command
        """
        super(Tool, self).__init__(*args, **kwargs)
        self._port = None
        self.exploits = exploits
        self.config = config
        self.port = port

    async def __call__(self, *args, **kwargs):
        """
        Called by task managers

        """
        return await self.call(*args, **kwargs)

    async def call(self, *args, **kwargs):
        """
        It is main call for executor. Should be override by inherits classes
        """
        raise NotImplementedError

    @property
    def port(self) -> 'Port':
        """
        Port, which is under testing
        """
        return self._port

    @port.setter
    def port(self, val):
        self._port = val

    def additional_info(self):
        return "on {port}".format(port=self.port)
