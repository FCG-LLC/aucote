"""
Defines abstract Tool class

"""
from multiprocessing import Lock

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
        self.lock = Lock()
        self._port = None
        self.executor = executor
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

    def get_info(self):
        """
        Obtain information related to tool

        Returns:
            dict

        """
        return {
            'port': str(self.port)
        }

    @property
    def port(self):
        with self.lock:
            return self._port

    @port.setter
    def port(self, val):
        with self.lock:
            self._port = val
