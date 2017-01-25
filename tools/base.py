"""
Defines abstract Tool class

"""
from aucote_cfg import cfg
from utils.exceptions import ImproperConfigurationException
from utils.task import Task


class Tool(Task):
    """
    Tool is a object, which can execute one of more scripts, e.g. Nmap, Hydra

    """
    def __init__(self, exploits, port, config, *args, **kwargs):
        """
        Init values needed to run and proceed command

        Args:
            executor: tasks executor
            exploits: list of exploits for using by tool
            port: port used by tool
            config: tool configuration

        """
        super(Tool, self).__init__(*args, **kwargs)
        self._port = None
        self.exploits = exploits
        self.config = config
        self.port = port

    def __call__(self, *args, **kwargs):
        """
        Called by task managers

        """
        self.call(*args, **kwargs)

    def call(self, *args, **kwargs):
        """
        It is main call for executor. Should be override by inherits classes

        Args:
            *args:
            **kwargs:

        Returns:

        """
        raise NotImplementedError

    @classmethod
    def get_config(cls, key):
        """
        Get configuration in suitable format (dict, list)

        Args:
            key (str): configuration key

        Returns:
            Configuration variable

        Raises:
            ImproperConfigurationException

        """
        try:
            return cfg.get(key).cfg
        except KeyError:
            raise ImproperConfigurationException(key)

    @property
    def port(self):
        """
        Port, which is under testing

        Returns:
            Port

        """
        with self._lock:
            return self._port

    @port.setter
    def port(self, val):
        with self._lock:
            self._port = val
