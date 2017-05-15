"""
Provides base class for Masscan

"""
from tools.common.command import Command
from tools.common.parsers import XMLParser


class MasscanBase(Command):
    """
    Base for all classes using masscan application.

    """
    COMMON_ARGS = ('-oX', '-')
    NAME = 'masscan'
    parser = XMLParser()
