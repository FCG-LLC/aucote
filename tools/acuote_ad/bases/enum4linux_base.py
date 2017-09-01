from tools.acuote_ad.parsers.enum4linux_parser import Enum4linuxParser
from tools.common import Command


class Enum4linuxBase(Command):
    """
    Enum4Linux base class

    """
    COMMON_ARGS = ('-o',)
    NAME = 'enum4linux.pl'
    CMD = 'enum4linux.pl'
    parser = Enum4linuxParser()
