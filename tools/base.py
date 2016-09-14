"""
Defines abstract Tool class

"""
from aucote_cfg import cfg
from utils.exceptions import ImproperConfigurationException


class Tool(object):
    """
    Tool is a object, which can execute one of more scripts, e.g. Nmap, Hydra

    """
    def __init__(self, executor, exploits, port, config):
        """
        Init values needed to run and proceed command

        Args:
            executor: tasks executor
            exploits: list of exploits for using by tool
            port: port used by tool
            config: tool configuration

        """
        self.executor = executor
        self.exploits = exploits
        self.config = config
        self.port = port

    def __call__(self, *args, **kwargs):
        """
        Called by task managers
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
