from aucote_cfg import cfg
from ..common import Command
class MasscanBase(Command):
    '''
    Base for all classes using masscan application.
    '''
    COMMON_ARGS = ('-oX', '-')
    NAME = 'masscan'