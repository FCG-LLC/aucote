from ..common import Command
class MasscanBase(Command):
    '''
    Base for all classes using masscan application.
    '''
    COMMON_ARGS = ('-oX', '-', '--ports', '0-1000') #'0-65535'
    NAME = 'masscan'